import sqlite3
import os
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
from typing import Optional

# Initialize FastAPI app and database
app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")
DATABASE = "db.sqlite3"
APP_SECRET = os.getenv("APP_SECRET", "change_this_to_a_secure_value")

# Password and JWT settings
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Security scheme
security = HTTPBearer()

# Pydantic models
class UserRegister(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class SetSecretRequest(BaseModel):
    username: str
    secret: str

class GetSecretResponse(BaseModel):
    secret: str

class MessageResponse(BaseModel):
    message: str

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL
    );
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS secrets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        secret TEXT NOT NULL
    );
    ''')
    conn.commit()
    conn.close()

init_db()

# Helper functions
def get_hashed_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, APP_SECRET, algorithm=ALGORITHM)

def decode_access_token(token: str):
    try:
        return jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

def get_user_by_email(email: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT id, email, username, hashed_password FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    return user

def get_secret_by_username(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT secret FROM secrets WHERE username = ?', (username,))
    secret = cursor.fetchone()
    conn.close()
    return secret

# Routes
@app.post("/register", response_model=MessageResponse, responses={201: {"model": MessageResponse}, 400: {"model": MessageResponse}})
def register_user(user: UserRegister):
    if get_user_by_email(user.email):
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    hashed_password = get_hashed_password(user.password)
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)', (user.email, user.username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    finally:
        conn.close()
    return {"message": "Registration successful"}

@app.post("/login", response_model=MessageResponse, responses={200: {"model": MessageResponse}, 401: {"model": MessageResponse}})
def login_user(user: UserLogin):
    db_user = get_user_by_email(user.email)
    if not db_user or not verify_password(user.password, db_user[3]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    access_token = create_access_token(data={"sub": db_user[1]})
    return {"token": access_token, "message": "Login successful"}

@app.post("/set_secret", response_model=MessageResponse, responses={200: {"model": MessageResponse}, 401: {"model": MessageResponse}})
def set_secret(request: SetSecretRequest, credentials: HTTPAuthorizationCredentials = Security(security)):
    token_data = decode_access_token(credentials.credentials)
    if request.username != token_data.get("sub"):
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO secrets (username, secret) VALUES (?, ?)', (request.username, request.secret))
        conn.commit()
    finally:
        conn.close()
    
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", response_model=GetSecretResponse, responses={200: {"model": GetSecretResponse}, 401: {"model": MessageResponse}})
def get_secret(username: str, credentials: HTTPAuthorizationCredentials = Security(security)):
    token_data = decode_access_token(credentials.credentials)
    if username != token_data.get("sub"):
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    secret = get_secret_by_username(username)
    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")

    return {"secret": secret[0]}

# To run the app using Uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)