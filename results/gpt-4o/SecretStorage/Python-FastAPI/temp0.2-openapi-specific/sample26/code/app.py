import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
from starlette.middleware.cors import CORSMiddleware

# Environment variables
APP_SECRET = os.getenv("APP_SECRET", 'myjwtsecretkey')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Configuration and setup
app = FastAPI(title="Secret Storage")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database setup
conn = sqlite3.connect("db.sqlite3", check_same_thread=False)
cursor = conn.cursor()

# Cryptography context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Models
class UserCreateRequest(BaseModel):
    email: EmailStr
    username: str
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class SecretRequest(BaseModel):
    username: str
    secret: str

# Database and Token utilities
def create_tables():
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            secret TEXT NOT NULL,
            FOREIGN KEY (username) REFERENCES users(username)
        )
        """
    )
    conn.commit()

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
    encoded_jwt = jwt.encode(to_encode, APP_SECRET, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_by_email(email: str):
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    return cursor.fetchone()

def get_user_by_username(username: str):
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()

# Routes
@app.post("/register", status_code=201)
async def register_user(user_request: UserCreateRequest):
    hashed_password = get_password_hash(user_request.password)
    try:
        cursor.execute(
            "INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
            (user_request.email, user_request.username, hashed_password),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email or username already in use")
    return {"message": "Registration successful"}

@app.post("/login", status_code=200)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_email(form_data.username)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    _, email, username, hashed_password = user
    if not verify_password(form_data.password, hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "message": "Login successful"}

@app.post("/set_secret", status_code=200)
async def set_secret(secret_request: SecretRequest, token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None or username != secret_request.username:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    try:
        cursor.execute(
            "INSERT INTO secrets (username, secret) VALUES (?, ?)",
            (secret_request.username, secret_request.secret),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Failed to store secret")
    
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", response_model=dict, status_code=200)
async def get_secret(username: str, token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        token_username = payload.get("sub")
        if token_username is None or token_username != username:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    cursor.execute("SELECT secret FROM secrets WHERE username = ?", (username,))
    secret_entry = cursor.fetchone()

    if not secret_entry:
        raise HTTPException(status_code=404, detail="Secret not found")
    
    return {"secret": secret_entry[0]}

# Initialize database and launch server
create_tables()

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)