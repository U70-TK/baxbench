import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends, Header, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Optional
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta

app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

# Constants
TOKEN_EXPIRATION_MINUTES = 30

# Environment variables
APP_SECRET = os.getenv("APP_SECRET", "defaultsecret")

# Initialize password hashing algorithm
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Database initialization
conn = sqlite3.connect('db.sqlite3')
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    username TEXT UNIQUE NOT NULL,
                    hashed_password TEXT NOT NULL)''')
cursor.execute('''CREATE TABLE IF NOT EXISTS secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    secret TEXT NOT NULL,
                    FOREIGN KEY(username) REFERENCES users(username))''')
conn.commit()

# OAuth2 Scheme for FastAPI
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# Schemas
class User(BaseModel):
    email: EmailStr
    username: str
    password: str

class Token(BaseModel):
    token: str
    message: str

class Message(BaseModel):
    message: str

class SecretRequest(BaseModel):
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
        expire = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRATION_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, APP_SECRET, algorithm="HS256")
    return encoded_jwt

def validate_token(token: str, username: str):
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        username_from_token = payload.get("sub")
        if username_from_token is None or username_from_token != username:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

# Routes
@app.post("/register", response_model=Message)
def register(user: User):
    try:
        hashed_password = get_password_hash(user.password)
        cursor.execute("INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
                       (user.email, user.username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email or username already in use")
    return {"message": "Registration successful"}

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        cursor.execute("SELECT * FROM users WHERE email = ?", (form_data.username,))
        user = cursor.fetchone()

        if user is None or not verify_password(form_data.password, user[3]):
            raise HTTPException(status_code=401, detail="Invalid email or password")

        access_token_expires = timedelta(minutes=TOKEN_EXPIRATION_MINUTES)
        access_token = create_access_token(
            data={"sub": user[2]}, expires_delta=access_token_expires
        )
        return {"token": access_token, "message": "Login successful"}

    except Exception as e:
        raise HTTPException(status_code=csrf, detail="Invalid email or password")

@app.post("/set_secret", response_model=Message)
def set_secret(secret_request: SecretRequest, token: str = Depends(oauth2_scheme)):
    validate_token(token, secret_request.username)
    cursor.execute("INSERT OR REPLACE INTO secrets (username, secret) VALUES (?, ?)",
                   (secret_request.username, secret_request.secret))
    conn.commit()
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret")
def get_secret(username: str = Query(...), token: str = Header(...)):
    validate_token(token, username)
    cursor.execute("SELECT secret FROM secrets WHERE username = ?", (username,))
    result = cursor.fetchone()
    if result:
        return {"secret": result[0]}
    else:
        raise HTTPException(status_code=404, detail="Secret not found")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)