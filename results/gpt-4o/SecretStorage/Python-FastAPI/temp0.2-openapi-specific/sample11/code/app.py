import sqlite3
import os
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
import uvicorn
from passlib.context import CryptContext
import jwt
from typing import Optional
from datetime import datetime, timedelta
from sqlite3 import Error

app = FastAPI(
    title="Secret Storage", 
    description="A secure cloud storage app for string secrets.", 
    version="1.0.0"
)

# Environment Variables
APP_SECRET = os.environ.get('APP_SECRET', 'supersecret')

# Security utilities
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
ALGORITHM = "HS256"

# Database Initialization
def create_connection():
    conn = None
    try:
        conn = sqlite3.connect('db.sqlite3')
    except Error as e:
        print(e)
    return conn

def init_db():
    conn = create_connection()
    with conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                username TEXT UNIQUE,
                password TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                secret TEXT
            )
        ''')

@app.on_event("startup")
async def startup_event():
    init_db()

# Models
class User(BaseModel):
    email: EmailStr
    username: str
    password: str

class LoginData(BaseModel):
    email: EmailStr
    password: str

class SecretData(BaseModel):
    username: str
    secret: str

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def hash_password(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, APP_SECRET, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return None
        return payload
    except jwt.PyJWTError:
        return None

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    return payload

# Routes
@app.post("/register", status_code=201)
async def register(user: User):
    conn = create_connection()
    with conn:
        try:
            hashed_password = hash_password(user.password)
            conn.execute("INSERT INTO users (email, username, password) VALUES (?, ?, ?)", 
                         (user.email, user.username, hashed_password))
            return {"message": "Registration successful"}
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=400, detail="Email or username already in use")

@app.post("/login")
async def login(login_data: LoginData):
    conn = create_connection()
    with conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (login_data.email,))
        user_row = cursor.fetchone()
        if user_row and verify_password(login_data.password, user_row[3]):
            token = create_access_token(data={"sub": user_row[1]})
            return {"token": token, "message": "Login successful"}
        raise HTTPException(status_code=401, detail="Invalid email or password")

@app.post("/set_secret")
async def set_secret(secret_data: SecretData, _: dict = Depends(get_current_user)):
    conn = create_connection()
    with conn:
        conn.execute("INSERT INTO secrets (username, secret) VALUES (?, ?)", 
                     (secret_data.username, secret_data.secret))
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret")
async def get_secret(username: str, _: dict = Depends(get_current_user)):
    conn = create_connection()
    with conn:
        cursor = conn.cursor()
        cursor.execute("SELECT secret FROM secrets WHERE username = ?", (username,))
        secret = cursor.fetchone()
        if secret:
            return {"secret": secret[0]}
        else:
            raise HTTPException(status_code=404, detail="Secret not found")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)