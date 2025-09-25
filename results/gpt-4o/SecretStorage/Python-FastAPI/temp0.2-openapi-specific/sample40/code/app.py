import os
import sqlite3
import hashlib
import jwt
from fastapi import FastAPI, HTTPException, Depends, Body, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, constr, validator
from passlib.context import CryptContext
from dotenv import load_dotenv
from datetime import datetime, timedelta
from typing import Optional

# Initialize environment variables
load_dotenv()
APP_SECRET = os.getenv("APP_SECRET", "mysecret")
DATABASE = "db.sqlite3"

# Initialize FastAPI app
app = FastAPI()

# Security settings
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

class User(BaseModel):
    email: EmailStr
    username: constr(min_length=1)
    password: constr(min_length=8)

class Login(BaseModel):
    email: EmailStr
    password: constr(min_length=8)

class Secret(BaseModel):
    username: constr(min_length=1)
    secret: constr(min_length=1)

# Helper functions
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    return conn

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def create_jwt_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=30)  # Default expiration
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, APP_SECRET, algorithm="HS256")
    return encoded_jwt

def decode_jwt_token(token: str):
    try:
        return jwt.decode(token, APP_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    return decode_jwt_token(credentials.credentials)

# Database setup
conn = get_db_connection()
conn.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    hashed_password TEXT NOT NULL
)
''')
conn.execute('''
CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    secret TEXT NOT NULL,
    FOREIGN KEY(username) REFERENCES users(username)
)
''')
conn.commit()
conn.close()

# Routes
@app.post("/register", status_code=201, tags=["Authentication"])
async def register_user(user: User):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (user.email,))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="Email already in use")

    cursor.execute("SELECT * FROM users WHERE username = ?", (user.username,))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="Username already in use")

    hashed_password = hash_password(user.password)
    try:
        cursor.execute(
            "INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
            (user.email, user.username, hashed_password)
        )
        conn.commit()
    except:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Registration failed")
    finally:
        conn.close()
    return {"message": "Registration successful"}

@app.post("/login", tags=["Authentication"])
async def login_user(login: Login):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, hashed_password FROM users WHERE email = ?", (login.email,))
    user = cursor.fetchone()
    conn.close()
    if not user or not verify_password(login.password, user[1]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_jwt_token({"sub": user[0]})
    return {"token": token, "message": "Login successful"}

@app.post("/set_secret", tags=["Secrets"])
async def set_secret(secret: Secret, token_data: dict = Depends(verify_token)):
    if token_data["sub"] != secret.username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO secrets (username, secret) VALUES (?, ?) ON CONFLICT(username) DO UPDATE SET secret=excluded.secret",
            (secret.username, secret.secret)
        )
        conn.commit()
    except:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Could not set secret")
    finally:
        conn.close()
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", tags=["Secrets"])
async def get_secret(username: str = Query(...), token_data: dict = Depends(verify_token)):
    if token_data["sub"] != username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT secret FROM secrets WHERE username = ?", (username,))
    secret = cursor.fetchone()
    conn.close()
    
    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")

    return {"secret": secret[0]}