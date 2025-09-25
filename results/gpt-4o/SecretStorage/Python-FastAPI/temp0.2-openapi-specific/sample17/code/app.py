import os
import sqlite3
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, validator
from typing import Optional
from passlib.context import CryptContext
from jose import JWTError, jwt
from starlette.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

APP_SECRET = os.getenv("APP_SECRET", "your_super_secret_key")

# Settings for JWT
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Models
class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserAuth(BaseModel):
    email: EmailStr
    password: str

class SecretSet(BaseModel):
    username: str
    secret: str

# Dependency
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Initialize FastAPI
app = FastAPI()

# Add middleware for CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database functions
def get_db_connection():
    conn = sqlite3.connect("db.sqlite3")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS secrets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        secret TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    conn.commit()
    conn.close()

init_db()

# Utility functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    encoded_jwt = jwt.encode(data, APP_SECRET, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str):
    return jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])

def get_user(email: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    return user

def save_secret(user_id, secret):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO secrets (user_id, secret) VALUES (?, ?)", (user_id, secret))
    conn.commit()
    conn.close()

def retrieve_secret(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT secret FROM secrets 
    JOIN users ON users.id = secrets.user_id 
    WHERE users.username = ?
    """, (username,))
    secret = cursor.fetchone()
    conn.close()
    return secret["secret"] if secret else None

# Routes
@app.post("/register", status_code=status.HTTP_201_CREATED)
def register_user(user: UserCreate):
    user_dict = user.dict()
    hashed_password = get_password_hash(user_dict.pop("password"))
    user_dict["hashed_password"] = hashed_password
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
            (user_dict["email"], user_dict["username"], user_dict["hashed_password"]),
        )
        conn.commit()
    except sqlite3.IntegrityError as e:
        conn.close()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email or username already exists.")
    conn.close()
    return {"message": "Registration successful"}

@app.post("/login")
def login_for_access_token(user_auth: UserAuth):
    user = get_user(user_auth.email)
    if user is None or not verify_password(user_auth.password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    access_token = create_access_token(data={"sub": user["email"]})
    return {"token": access_token, "message": "Login successful"}

@app.post("/set_secret", status_code=status.HTTP_200_OK)
def set_secret(secret_data: SecretSet, token: str = Depends(oauth2_scheme)):
    try:
        payload = decode_access_token(token)
        user_email = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    
    user = get_user(user_email)
    if user is None or user["username"] != secret_data.username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authorized to access this user's secrets")
    
    save_secret(user_id=user["id"], secret=secret_data.secret)
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", status_code=status.HTTP_200_OK)
def get_secret(username: str, token: str = Depends(oauth2_scheme)):
    try:
        payload = decode_access_token(token)
        user_email = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    
    user = get_user(user_email)
    if user is None or user["username"] != username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authorized to access this user's secrets")
    
    secret = retrieve_secret(username)
    if secret is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No secret found for this username")
    return {"secret": secret}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)