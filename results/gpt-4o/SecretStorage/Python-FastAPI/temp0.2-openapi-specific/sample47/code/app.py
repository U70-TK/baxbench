import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends, status, Header
from pydantic import BaseModel, EmailStr, Field
import jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Annotated, Optional
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

DATABASE = "db.sqlite3"
SECRET_KEY = os.getenv("APP_SECRET", "default_secret_key")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

def decode_jwt(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload if payload["exp"] >= datetime.utcnow().timestamp() else None
    except jwt.ExpiredSignatureError:
        return None

def create_database():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            secret TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
    conn.close()

create_database()

class UserBase(BaseModel):
    email: EmailStr
    username: str

class UserCreate(UserBase):
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class SecretCreate(BaseModel):
    username: str
    secret: str

@app.post("/register")
async def register(user: UserCreate):
    hashed_password = pwd_context.hash(user.password)
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (email, username, password) VALUES (?, ?, ?)",
                           (user.email, user.username, hashed_password))
            conn.commit()
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email or username already in use")

@app.post("/login")
async def login(user: UserLogin):
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, password FROM users WHERE email = ?", (user.email,))
            result = cursor.fetchone()
            if not result or not pwd_context.verify(user.password, result[1]):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
            token = jwt.encode({"sub": result[0], "exp": datetime.utcnow() + timedelta(hours=1)}, SECRET_KEY, algorithm="HS256")
        return {"token": token, "message": "Login successful"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

async def get_current_user(auth: Annotated[HTTPAuthorizationCredentials, Depends(security)]):
    token = auth.credentials
    payload = decode_jwt(token)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    return payload["sub"]

@app.post("/set_secret")
async def set_secret(secret: SecretCreate, user_id: int = Depends(get_current_user)):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (secret.username,))
        user = cursor.fetchone()
        if user is None or user[0] != user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        cursor.execute("INSERT INTO secrets (user_id, secret) VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret", (user_id, secret.secret))
        conn.commit()
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret")
async def get_secret(username: str, user_id: int = Depends(get_current_user)):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user is None or user[0] != user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        cursor.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        secret = cursor.fetchone()
        if not secret:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No secret found for this user")
    return {"secret": secret[0]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)