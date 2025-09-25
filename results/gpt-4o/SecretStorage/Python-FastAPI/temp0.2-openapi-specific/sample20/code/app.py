import os
import sqlite3
import hashlib
import jwt
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, validator
from passlib.context import CryptContext
from typing import Optional
from dotenv import load_dotenv
from starlette.responses import JSONResponse

load_dotenv()

# Constants
DATABASE = "db.sqlite3"
APP_SECRET = os.getenv("APP_SECRET", "default_secret")
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 30

# JWT and security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Initialize the application
app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

# Database initialization
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL
            )
            '''
        )
        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                secret TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            '''
        )
    conn.close()

init_db()

# Helper Functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
        
# Pydantic Models
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

# Dependencies
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token_data = decode_access_token(credentials.credentials)
    email = token_data.get('sub')
    if not email:
        raise HTTPException(status_code=401, detail="Invalid token")
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, username FROM users WHERE email=?", (email,))
        user = cursor.fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

# Routes
@app.post("/register", status_code=201)
async def register(user: UserRegister):
    try:
        hashed_password = get_password_hash(user.password)
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
                (user.email, user.username, hashed_password)
            )
            conn.commit()
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")

@app.post("/login", status_code=200)
async def login(user: UserLogin):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, hashed_password FROM users WHERE email=?", (user.email,))
        result = cursor.fetchone()
    if not result or not verify_password(user.password, result[2]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    access_token = create_access_token(data={"sub": user.email})
    return {"token": access_token, "message": "Login successful"}

@app.post("/set_secret", status_code=200)
async def set_secret(secret_request: SetSecretRequest, user=Depends(get_current_user)):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username=?", (secret_request.username,))
        result = cursor.fetchone()

    if not result or result[0] != user[0]:
        raise HTTPException(status_code=401, detail="Invalid authentication")

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO secrets (user_id, secret) VALUES (?, ?)", (user[0], secret_request.secret))
        conn.commit()

    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", status_code=200)
async def get_secret(username: str, credentials: HTTPAuthorizationCredentials = Depends(security)):
    user = get_current_user(credentials)
    
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT users.id FROM users WHERE users.username=?", (username,))
        user_data = cursor.fetchone()
    
    if not user_data or user_data[0] != user[0]:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT secret FROM secrets WHERE user_id=?", (user[0],))
        secret = cursor.fetchone()
    
    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")

    return {"secret": secret[0]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)