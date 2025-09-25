import os
import sqlite3
from passlib.context import CryptContext
from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import Union
from jose import JWTError, jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
import uvicorn

# Load environment variables
load_dotenv()
APP_SECRET = os.getenv("APP_SECRET", "changethissecret")
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Initialize FastAPI
app = FastAPI()

# Database setup
DATABASE = 'db.sqlite3'

# Security setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Utility functions and classes
def get_db_connection():
    try:
        conn = sqlite3.connect(DATABASE)
        return conn
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail="Database connection error")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, APP_SECRET, algorithm="HS256")
    return encoded_jwt

def authorize_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=403, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return username

def init_db():
    conn = get_db_connection()
    with conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            secret TEXT NOT NULL,
            FOREIGN KEY (username) REFERENCES users (username)
        )""")
    conn.close()

# Models
class UserRegister(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class SecretModel(BaseModel):
    username: str
    secret: str

# Routes
@app.post("/register", status_code=201)
def register(user: UserRegister):
    conn = get_db_connection()
    hashed_password = get_password_hash(user.password)
    try:
        with conn:
            conn.execute("INSERT INTO users (email, username, password) VALUES (?, ?, ?)",
                         (user.email, user.username, hashed_password))
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    return {"message": "Registration successful"}

@app.post("/token", response_model=OAuth2PasswordRequestForm)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, password FROM users WHERE email=?", (form_data.username,))
    result = cursor.fetchone()
    if result is None or not verify_password(form_data.password, result[1]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": result[0]}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/set_secret")
def set_secret(secret: SecretModel, current_user: str = Depends(authorize_user)):
    if current_user != secret.username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    conn = get_db_connection()
    with conn:
        conn.execute("INSERT OR REPLACE INTO secrets (username, secret) VALUES (?, ?)",
                     (secret.username, secret.secret))
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret")
def get_secret(username: str, current_user: str = Depends(authorize_user)):
    if current_user != username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT secret FROM secrets WHERE username=?", (username,))
    secret = cursor.fetchone()
    if secret is None:
        raise HTTPException(status_code=404, detail="Secret not found")
    return {"secret": secret[0]}

# Initialize the database
init_db()

# Start the server
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)