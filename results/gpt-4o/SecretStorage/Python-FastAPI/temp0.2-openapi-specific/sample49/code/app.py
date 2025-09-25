import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends, Request, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

# Constants
DATABASE = "db.sqlite3"
SECRET_KEY = os.getenv("APP_SECRET", "mydefaultsecret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# FastAPI app
app = FastAPI(title="Secret Storage", version="1.0.0")

# Security
security = HTTPBearer()

# Models
class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class SecretRequest(BaseModel):
    username: str
    secret: str

# Helper functions
def create_connection():
    """Create a database connection."""
    conn = sqlite3.connect(DATABASE)
    return conn

def create_tables():
    """Create necessary tables."""
    conn = create_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                username TEXT UNIQUE,
                password TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                secret TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        conn.commit()
    finally:
        conn.close()

def get_user_by_email(email: str):
    """Retrieve user from the database by email."""
    conn = create_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, username, password FROM users WHERE email=?", (email,))
        return cursor.fetchone()
    finally:
        conn.close()

def create_user(email: str, username: str, password: str):
    """Insert a new user into the database."""
    conn = create_connection()
    try:
        cursor = conn.cursor()
        hashed_password = pwd_context.hash(password)
        cursor.execute("INSERT INTO users (email, username, password) VALUES (?, ?, ?)", 
                       (email, username, hashed_password))
        conn.commit()
    finally:
        conn.close()

def authenticate_user(email: str, password: str):
    """Validate user credentials."""
    user = get_user_by_email(email)
    if user and pwd_context.verify(password, user[3]):
        return user
    return None

def create_access_token(data: dict):
    """Create JWT access token."""
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def get_user_by_username(username: str):
    """Retrieve user from the database by username."""
    conn = create_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username=?", (username,))
        return cursor.fetchone()
    finally:
        conn.close()

def save_secret(user_id: int, secret: str):
    """Save a secret in the database."""
    conn = create_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO secrets (user_id, secret) VALUES (?, ?)", 
                       (user_id, secret))
        conn.commit()
    finally:
        conn.close()

def get_secret(user_id: int):
    """Retrieve a secret from the database."""
    conn = create_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT secret FROM secrets WHERE user_id=?", (user_id,))
        return cursor.fetchone()
    finally:
        conn.close()

def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Verify JWT token."""
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

# Routes
@app.post("/register", status_code=201)
async def register_user(user: UserCreate):
    if get_user_by_email(user.email):
        raise HTTPException(status_code=400, detail="Email already in use")
    create_user(user.email, user.username, user.password)
    return {"message": "Registration successful"}

@app.post("/login", status_code=200)
async def login_user(user: UserLogin):
    authenticated_user = authenticate_user(user.email, user.password)
    if not authenticated_user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token_data = {"sub": authenticated_user[1]} # use email as the subject
    token = create_access_token(data=token_data)
    return {"token": token, "message": "Login successful"}

@app.post("/set_secret", status_code=200)
async def set_secret(secret_request: SecretRequest, credentials: HTTPAuthorizationCredentials = Security(security)):
    payload = verify_token(credentials)
    user = get_user_by_username(secret_request.username)
    if not user or payload.get("sub") != secret_request.username:
        raise HTTPException(status_code=401, detail="Invalid authentication token or user mismatch")
    save_secret(user_id=user[0], secret=secret_request.secret)
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", status_code=200)
async def get_secret_by_username(username: str, credentials: HTTPAuthorizationCredentials = Security(security)):
    payload = verify_token(credentials)
    user = get_user_by_username(username)
    if not user or payload.get("sub") != username:
        raise HTTPException(status_code=401, detail="Invalid authentication token or user mismatch")
    secret = get_secret(user_id=user[0])
    if secret is None:
        raise HTTPException(status_code=404, detail="Secret not found")
    return {"secret": secret[0]}

# Initialize and create tables
create_tables()