import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, SecretStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from typing import Optional
from starlette.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED
from fastapi import Request
from datetime import datetime, timedelta

# Constants for JWT token
SECRET_KEY = os.getenv("APP_SECRET", "your_fallback_app_secret_here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# FastAPI application
app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

# Security and DB setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

DATABASE_NAME = 'db.sqlite3'

def init_db():
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            email TEXT UNIQUE,
            username TEXT UNIQUE,
            hashed_password TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY,
            username TEXT,
            secret TEXT
        )
    ''')
    conn.commit()
    cursor.close()
    conn.close()

init_db()

# Pydantic models
class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: SecretStr

class LoginRequest(BaseModel):
    email: EmailStr
    password: SecretStr

class SecretSet(BaseModel):
    username: str
    secret: str

# Helper functions
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

def get_user(username: str):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username=?', (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    if user:
        return {"id": user[0], "email": user[1], "username": user[2], "hashed_password": user[3]}
    return None

def authenticate_user(email: str, password: str):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email=?', (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    if user and verify_password(password, user[3]):
        return {"id": user[0], "email": user[1], "username": user[2]}
    return None

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
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user

# API Endpoints
@app.post("/register", status_code=HTTP_201_CREATED)
async def register(user: UserCreate):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    hashed_password = get_password_hash(user.password.get_secret_value())
    try:
        cursor.execute('INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)',
                       (user.email, user.username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Email or username already in use")
    finally:
        cursor.close()
        conn.close()
    return {"message": "Registration successful"}

@app.post("/login", response_model=dict)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user['username']}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer", "message": "Login successful"}

@app.post("/set_secret")
async def set_secret(secret: SecretSet, current_user: dict = Depends(get_current_user)):
    if secret.username != current_user["username"]:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO secrets (username, secret) VALUES (?, ?)', (secret.username, secret.secret))
    conn.commit()
    cursor.close()
    conn.close()
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", response_model=dict)
async def get_secret(username: str, current_user: dict = Depends(get_current_user)):
    if username != current_user["username"]:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT secret FROM secrets WHERE username=?', (username,))
    secret_record = cursor.fetchone()
    cursor.close()
    conn.close()
    if not secret_record:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="No secret found")
    return {"secret": secret_record[0]}