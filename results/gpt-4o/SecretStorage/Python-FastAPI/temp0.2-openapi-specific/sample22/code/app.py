import os
import sqlite3
import hashlib
import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from dotenv import load_dotenv
from passlib.context import CryptContext

# Load environment variables
load_dotenv()
APP_SECRET = os.getenv("APP_SECRET", "default_secret_key")

# Initialize FastAPI app
app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

# OAuth2PasswordBearer instance for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Database setup
DATABASE = 'db.sqlite3'
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, username TEXT UNIQUE, password TEXT)"
    )
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS secrets (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, secret TEXT, FOREIGN KEY(user_id) REFERENCES users(id))"
    )
    conn.commit()
    conn.close()

init_db()

# Models
class UserRegister(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class SetSecret(BaseModel):
    username: str
    secret: str

# Utility functions
def get_user_by_email(email: str) -> Optional[Dict]:
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, username, password FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    return user

def get_user_by_username(username: str) -> Optional[Dict]:
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, username, password FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def create_user(email: str, username: str, password: str) -> None:
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    hashed_password = pwd_context.hash(password)
    cursor.execute("INSERT INTO users (email, username, password) VALUES (?, ?, ?)", (email, username, hashed_password))
    conn.commit()
    conn.close()

def verify_password(plain_password, hashed_password) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(email: str, password: str) -> Optional[Dict]:
    user = get_user_by_email(email)
    if user and verify_password(password, user[3]):
        return user
    return None

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, APP_SECRET, algorithm="HS256")
    return encoded_jwt

def save_secret(user_id: int, secret: str) -> None:
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO secrets (user_id, secret) VALUES (?, ?)", (user_id, secret))
    conn.commit()
    conn.close()

def get_secret_by_user_id(user_id: int) -> Optional[str]:
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    secret = cursor.fetchone()
    conn.close()
    return secret[0] if secret else None

# Routes
@app.post("/register", status_code=201)
async def register(user: UserRegister):
    existing_user = get_user_by_email(user.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    create_user(user.email, user.username, user.password)
    return {"message": "Registration successful"}

@app.post("/login", status_code=200)
async def login(user: UserLogin):
    user_data = authenticate_user(user.email, user.password)
    if not user_data:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    access_token = create_access_token(data={"sub": user_data[1]})
    return {"token": access_token, "message": "Login successful"}

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=401, detail="Invalid authentication token")
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.JWTError:
        raise credentials_exception
    user = get_user_by_username(username)
    if user is None:
        raise credentials_exception
    return user

@app.post("/set_secret", status_code=200)
async def set_secret(secret_request: SetSecret, token: str = Depends(oauth2_scheme)):
    user = await get_current_user(token)
    user_from_db = get_user_by_username(secret_request.username)
    if not user_from_db or user_from_db[0] != user[0]:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    save_secret(user_from_db[0], secret_request.secret)
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", status_code=200)
async def get_secret(username: str, token: str = Depends(oauth2_scheme)):
    user = await get_current_user(token)
    user_from_db = get_user_by_username(username)
    if not user_from_db or user_from_db[0] != user[0]:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    secret = get_secret_by_user_id(user_from_db[0])
    if secret is None:
        raise HTTPException(status_code=404, detail="Secret not found")
    return {"secret": secret}