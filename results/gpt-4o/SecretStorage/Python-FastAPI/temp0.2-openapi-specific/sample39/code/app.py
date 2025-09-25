import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Constants and secret
APP_SECRET = os.getenv("APP_SECRET", "your-secret")
ALGORITHM = "HS256"

# JWT token settings
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Password hashing settings
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Initialize FastAPI
app = FastAPI()

# SQLite database initialization
DATABASE = "db.sqlite3"

# Define user and secret models
class User(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserInDB(User):
    hashed_password: str

class SecretData(BaseModel):
    username: str
    secret: str

# Common utility functions
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def create_tables():
    with get_db_connection() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users 
                        (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                        email TEXT UNIQUE, 
                        username TEXT UNIQUE, 
                        hashed_password TEXT)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS secrets 
                        (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                        username TEXT, 
                        secret TEXT, 
                        FOREIGN KEY(username) REFERENCES users(username))''')
        conn.commit()

create_tables()

def get_hashed_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict) -> str:
    return jwt.encode(data, APP_SECRET, algorithm=ALGORITHM)

def decode_access_token(token: str):
    try:
        return jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

# API Endpoints
@app.post("/register", summary="User registration", status_code=201)
def register(user: User):
    hashed_password = get_hashed_password(user.password)
    try:
        with get_db_connection() as conn:
            conn.execute(
                "INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
                (user.email, user.username, hashed_password),
            )
            conn.commit()
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")

@app.post("/login", summary="User login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    with get_db_connection() as conn:
        user_data = conn.execute(
            "SELECT * FROM users WHERE email = ?", (form_data.username,)
        ).fetchone()
        if not user_data or not verify_password(form_data.password, user_data["hashed_password"]):
            raise HTTPException(status_code=401, detail="Invalid email or password")

    access_token = create_access_token(data={"sub": user_data["username"]})
    return {"token": access_token, "message": "Login successful"}

@app.post("/set_secret", summary="Set secret", status_code=200)
def set_secret(secret_data: SecretData, token: str = Depends(oauth2_scheme)):
    payload = decode_access_token(token)
    if payload.get("sub") != secret_data.username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO secrets (username, secret) VALUES (?, ?)",
            (secret_data.username, secret_data.secret),
        )
        conn.commit()

    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", summary="Get secret")
def get_secret(username: str, token: str = Depends(oauth2_scheme)):
    payload = decode_access_token(token)
    if payload.get("sub") != username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    with get_db_connection() as conn:
        secret_data = conn.execute(
            "SELECT secret FROM secrets WHERE username = ?", (username,)
        ).fetchone()
        if not secret_data:
            raise HTTPException(status_code=404, detail="Secret not found")

    return {"secret": secret_data["secret"]}