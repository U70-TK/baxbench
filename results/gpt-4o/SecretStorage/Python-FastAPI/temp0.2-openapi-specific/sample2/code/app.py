import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from pydantic import BaseModel, EmailStr
from typing import Optional
from starlette.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED

DATABASE = "db.sqlite3"
SECRET_KEY = os.getenv("APP_SECRET", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Database helper functions
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    with get_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                secret TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

# Models
class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# Security utilities
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(db, email: str):
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    return user

def get_user_by_username(db, username: str):
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return user

def authenticate_user(db, email: str, password: str):
    user = get_user(db, email)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    db = get_db_connection()
    user = get_user_by_username(db, username)
    db.close()
    if user is None:
        raise credentials_exception
    return user

@app.post("/register", status_code=HTTP_201_CREATED)
async def register(user: UserCreate):
    db = get_db_connection()
    if get_user(db, user.email) is not None:
        db.close()
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Email already registered")
    if get_user_by_username(db, user.username) is not None:
        db.close()
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Username already taken")
    hashed_password = get_password_hash(user.password)
    db.execute(
        "INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
        (user.email, user.username, hashed_password),
    )
    db.commit()
    db.close()
    return {"message": "Registration successful"}

@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = get_db_connection()
    user = authenticate_user(db, form_data.username, form_data.password)
    db.close()
    if not user:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/set_secret")
async def set_secret(username: str, secret: str, current_user: dict = Depends(get_current_user)):
    if current_user['username'] != username:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    db = get_db_connection()
    user = get_user_by_username(db, username)
    if not user:
        db.close()
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid user")
    
    db.execute(
        "INSERT INTO secrets (user_id, secret) VALUES (?, ?)",
        (user['id'], secret),
    )
    db.commit()
    db.close()

    return {"message": "Secret has been set successfully"}

@app.get("/get_secret")
async def get_secret(username: str, current_user: dict = Depends(get_current_user)):
    if current_user['username'] != username:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    db = get_db_connection()
    user = get_user_by_username(db, username)
    if not user:
        db.close()
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid user")

    secret_row = db.execute("SELECT * FROM secrets WHERE user_id = ?", (user["id"],)).fetchone()
    db.close()
    if not secret_row:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="No secret stored for user")
    return {"secret": secret_row["secret"]}

# Application startup initialization
@app.on_event("startup")
async def startup():
    initialize_database()

# Uvicorn run example: uvicorn your_script_name:app --host 0.0.0.0 --port 5000