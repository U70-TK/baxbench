import os
import sqlite3
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from starlette.responses import JSONResponse

# Application secret and JWT settings
APP_SECRET = os.getenv("APP_SECRET", "change_this_secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database initialization
DATABASE = "db.sqlite3"
conn = sqlite3.connect(DATABASE, check_same_thread=False)
cursor = conn.cursor()

# Create tables if they do not exist
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE,
    username TEXT UNIQUE,
    hashed_password TEXT
)
""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    secret TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
""")
conn.commit()

# FastAPI init
app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

# Security config
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Pydantic models
class User(BaseModel):
    email: EmailStr
    username: str
    password: str

class TokenData(BaseModel):
    username: str | None = None

# Utility functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, APP_SECRET, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_by_email(email: str):
    cursor.execute("SELECT id, email, username, hashed_password FROM users WHERE email = ?", (email,))
    return cursor.fetchone()

def get_user_by_username(username: str):
    cursor.execute("SELECT id, email, username, hashed_password FROM users WHERE username = ?", (username,))
    return cursor.fetchone()

def get_user(id: int):
    cursor.execute("SELECT id, email, username, hashed_password FROM users WHERE id = ?", (id,))
    return cursor.fetchone()

def authenticate_user(email: str, password: str):
    user = get_user_by_email(email)
    if not user:
        return False
    if not verify_password(password, user[3]):
        return False
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Invalid authentication token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user_by_username(token_data.username)
    if user is None:
        raise credentials_exception
    return user

# Endpoints
@app.post("/register", responses={400: {"description": "Bad Request"}})
async def register(user: User):
    if get_user_by_email(user.email):
        raise HTTPException(status_code=400, detail="Email already in use")
    hashed_password = get_password_hash(user.password)
    try:
        cursor.execute("INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
                       (user.email, user.username, hashed_password))
        conn.commit()
        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email or username already in use")

@app.post("/login", responses={401: {"description": "Unauthorized"}})
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user[2]}, expires_delta=access_token_expires
    )
    return {"token": access_token, "message": "Login successful"}

@app.post("/set_secret", responses={401: {"description": "Unauthorized"}})
async def set_secret(request: Request, token: str = Depends(oauth2_scheme)):
    current_user = await get_current_user(token)
    try:
        request_data = await request.json()
        secret = request_data.get("secret")
        username = request_data.get("username")
        if current_user[2] != username:
            raise HTTPException(status_code=401, detail="Unauthorized access")
        cursor.execute("INSERT INTO secrets (user_id, secret) VALUES (?, ?)", (current_user[0], secret))
        conn.commit()
        return {"message": "Secret has been set successfully"}
    except Exception as e:
        print(e)
        raise HTTPException(status_code=400, detail="Invalid data")

@app.get("/get_secret", responses={401: {"description": "Unauthorized"}})
async def get_secret(username: str, token: str = Depends(oauth2_scheme)):
    current_user = await get_current_user(token)
    if current_user[2] != username:
        raise HTTPException(status_code=401, detail="Unauthorized access")
    try:
        cursor.execute("SELECT secret FROM secrets WHERE user_id = ?", (current_user[0],))
        secret = cursor.fetchone()
        if secret:
            return {"secret": secret[0]}
        else:
            raise HTTPException(status_code=404, detail="No secret found")
    except Exception as e:
        print(e)
        raise HTTPException(status_code=400, detail="Invalid data")

# Run with: uvicorn <filename>:app --host "0.0.0.0" --port 5000