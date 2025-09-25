import os
import sqlite3
import uvicorn
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from typing import Optional
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
APP_SECRET = os.getenv("APP_SECRET", "change_this_to_a_secure_string")

# FastAPI app and middleware
middleware = [
    Middleware(SessionMiddleware, secret_key=APP_SECRET)
]

app = FastAPI(middleware=middleware)

# Database setup
DATABASE = 'db.sqlite3'
conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    hashed_password TEXT NOT NULL
)
''')
cursor.execute('''
CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    secret TEXT NOT NULL
)
''')
conn.commit()

# Security setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Helper functions
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[int] = None):
    return jwt.encode(data, APP_SECRET, algorithm="HS256")

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        return payload
    except JWTError:
        return None

def authenticate_user(email: str, password: str):
    cursor = conn.cursor()
    cursor.execute("SELECT username, hashed_password FROM users WHERE email = ?", (email,))
    result = cursor.fetchone()
    if result:
        username, hashed_password = result
        if verify_password(password, hashed_password):
            return username
    return None

# Pydantic models
class UserRegistration(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class SetSecret(BaseModel):
    username: str
    secret: str

# Routes
@app.post("/register", status_code=status.HTTP_201_CREATED)
def register_user(user: UserRegistration):
    hashed_password = get_password_hash(user.password)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
            (user.email, user.username, hashed_password)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email or username already in use"
        )
    return {"message": "Registration successful"}

@app.post("/login", response_model=dict)
def login_user(form_data: OAuth2PasswordRequestForm = Depends()):
    username = authenticate_user(form_data.username, form_data.password)
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": username})
    return {"access_token": access_token, "token_type": "bearer", "message": "Login successful"}

@app.post("/set_secret", status_code=status.HTTP_200_OK)
def set_secret(secret_data: SetSecret, token: str = Depends(oauth2_scheme)):
    payload = decode_access_token(token)
    if payload is None or payload.get('sub') != secret_data.username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token"
        )
    
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO secrets (username, secret) VALUES (?, ?)",
        (secret_data.username, secret_data.secret)
    )
    conn.commit()
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", status_code=status.HTTP_200_OK)
def get_secret(username: str, token: str = Depends(oauth2_scheme)):
    payload = decode_access_token(token)
    if payload is None or payload.get('sub') != username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token"
        )

    cursor = conn.cursor()
    cursor.execute("SELECT secret FROM secrets WHERE username = ?", (username,))
    secret = cursor.fetchone()
    if secret is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found for this user"
        )
    return {"secret": secret[0]}

# Run the application
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)