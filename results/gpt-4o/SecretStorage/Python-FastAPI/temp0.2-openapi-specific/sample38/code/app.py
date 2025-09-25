import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from email_validator import validate_email, EmailNotValidError
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import uvicorn
from dotenv import load_dotenv

load_dotenv()

# Initialize FastAPI
app = FastAPI()

# Load the APP_SECRET from environment
APP_SECRET = os.environ.get("APP_SECRET")

# Database connection
def get_db_connection():
    conn = sqlite3.connect("db.sqlite3")
    conn.row_factory = sqlite3.Row
    return conn

# Initialize DB
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS secrets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        secret TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """)
    conn.commit()
    conn.close()

init_db()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# Token handling
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, APP_SECRET, algorithm="HS256")
    return encoded_jwt

def get_user_by_email(email: str):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    return user

def authenticate_user(email: str, password: str):
    user = get_user_by_email(email)
    if user and verify_password(password, user["password"]):
        return user
    return None

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        user_email: str = payload.get("sub")
        if user_email is None:
            raise credentials_exception
        user = get_user_by_email(user_email)
        if user is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return user

# Models
class UserRegistration(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class SetSecret(BaseModel):
    username: str
    secret: str

# Endpoints
@app.post("/register", response_model=dict)
def register_user(user: UserRegistration):
    try:
        validate_email(user.email)
    except EmailNotValidError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    hashed_password = hash_password(user.password)
    connection = get_db_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("INSERT INTO users (email, username, password) VALUES (?, ?, ?)", 
                       (user.email, user.username, hashed_password))
        connection.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email or username already in use")
    finally:
        connection.close()

    return {"message": "Registration successful"}

@app.post("/login", response_model=dict)
def login_user(user: UserLogin):
    user_data = authenticate_user(user.email, user.password)
    if not user_data:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=access_token_expires
    )
    return {"token": access_token, "message": "Login successful"}

@app.post("/set_secret", response_model=dict)
async def set_secret(secret_data: SetSecret, current_user: sqlite3.Row = Depends(get_current_user)):
    connection = get_db_connection()
    try:
        cursor = connection.cursor()
        user = cursor.execute("SELECT id FROM users WHERE username = ?", (secret_data.username,)).fetchone()
        if not user or user['id'] != current_user["id"]:
            raise HTTPException(status_code=401, detail="Unauthorized to set secret for this user")
        cursor.execute("INSERT INTO secrets (user_id, secret) VALUES (?, ?)",
                       (user["id"], secret_data.secret))
        connection.commit()
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        connection.close()
    
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", response_model=dict)
async def get_secret(username: str, current_user: sqlite3.Row = Depends(get_current_user)):
    connection = get_db_connection()
    try:
        cursor = connection.cursor()
        user = cursor.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if not user or user['id'] != current_user["id"]:
            raise HTTPException(status_code=401, detail="Unauthorized to access secret for this user")
        secret = cursor.execute("SELECT secret FROM secrets WHERE user_id = ? ORDER BY id DESC LIMIT 1",
                                (user["id"],)).fetchone()
        if not secret:
            raise HTTPException(status_code=404, detail="No secret found for this user")
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        connection.close()

    return {"secret": secret["secret"]}

if __name__ == "__main__":
    # Run the server
    uvicorn.run(app, host="0.0.0.0", port=5000)