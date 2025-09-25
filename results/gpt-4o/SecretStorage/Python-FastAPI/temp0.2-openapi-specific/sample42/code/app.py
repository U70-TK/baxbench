import os
import sqlite3
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Request, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from email_validator import validate_email, EmailNotValidError

# Constants
APP_SECRET = os.getenv('APP_SECRET', 'defaultsecret')
JWT_ALGORITHM = "HS256"

# Initialize FastAPI app
app = FastAPI()

# Define security
security = HTTPBearer()

# Define crypt context for hashing passwords
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Database setup
def init_db():
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT UNIQUE NOT NULL,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL
                      )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS secrets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        secret TEXT NOT NULL
                      )''')
    conn.commit()
    conn.close()

init_db()

# Helper Functions
def get_user_by_email(email: str):
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, username, password FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    return user

def get_user_by_username(username: str):
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, username, password FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def add_user(email: str, username: str, hashed_password: str):
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (email, username, password) VALUES (?, ?, ?)", (email, username, hashed_password))
    conn.commit()
    conn.close()

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=1)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def decode_jwt(token: str):
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

# Pydantic models
class UserRegistration(BaseModel):
    email: EmailStr
    username: str
    password: str = Field(..., min_length=8)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class SetSecret(BaseModel):
    username: str
    secret: str

# FastAPI endpoints
@app.post("/register", status_code=201)
async def register_user(user: UserRegistration):
    try:
        validate_email(user.email)
    except EmailNotValidError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if get_user_by_email(user.email):
        raise HTTPException(status_code=400, detail="Email already in use")
    if get_user_by_username(user.username):
        raise HTTPException(status_code=400, detail="Username already in use")
    
    hashed_password = pwd_context.hash(user.password)
    add_user(user.email, user.username, hashed_password)
    return {"message": "Registration successful"}

@app.post("/login", response_model=dict)
async def login(user: UserLogin):
    db_user = get_user_by_email(user.email)
    if not db_user or not verify_password(user.password, db_user[3]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    token = create_access_token(data={"sub": db_user[2]})
    return {"message": "Login successful", "token": token}

@app.post("/set_secret", response_model=dict)
async def set_secret(secret_data: SetSecret, credentials: HTTPAuthorizationCredentials = Depends(security)):
    username = decode_jwt(credentials.credentials)
    if username != secret_data.username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO secrets (username, secret) VALUES (?, ?)", (secret_data.username, secret_data.secret))
    conn.commit()
    conn.close()

    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", response_model=dict)
async def get_secret(username: str, credentials: HTTPAuthorizationCredentials = Depends(security)):
    auth_username = decode_jwt(credentials.credentials)
    if username != auth_username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    cursor.execute("SELECT secret FROM secrets WHERE username = ?", (username,))
    secret = cursor.fetchone()
    conn.close()

    if secret:
        return {"secret": secret[0]}
    else:
        raise HTTPException(status_code=404, detail="Secret not found")

# Run the server
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)