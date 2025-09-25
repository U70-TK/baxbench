import sqlite3
import os
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, constr
from starlette.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED
from contextlib import contextmanager
from typing import Optional

# Load app secret
APP_SECRET = os.getenv("APP_SECRET", "your-app-secret")

# Create the FastAPI app
app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

# Security settings
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Database setup
DB_NAME = 'db.sqlite3'

@contextmanager
def db_connection():
    conn = sqlite3.connect(DB_NAME)
    try:
        yield conn
    finally:
        conn.close()

def create_db():
    with db_connection() as conn:
        conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            username TEXT,
            hashed_password TEXT
        )
        ''')
        conn.execute('''
        CREATE TABLE IF NOT EXISTS secrets (
            username TEXT PRIMARY KEY,
            secret TEXT
        )
        ''')
        conn.commit()

create_db()

class UserRegistration(BaseModel):
    email: EmailStr
    username: constr(strip_whitespace=True, min_length=3)
    password: constr(min_length=6)

class UserLogin(BaseModel):
    email: EmailStr
    password: constr(min_length=6)

class SecretModel(BaseModel):
    username: str
    secret: str

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(email: str):
    return jwt.encode({"sub": email}, APP_SECRET, algorithm="HS256")

def verify_token(credentials: HTTPAuthorizationCredentials):
    try:
        payload = jwt.decode(credentials.credentials, APP_SECRET, algorithms=["HS256"])
        return payload["sub"]
    except JWTError:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

@app.post("/register", status_code=HTTP_201_CREATED)
def register_user(user: UserRegistration):
    with db_connection() as conn:
        try:
            hashed_password = get_password_hash(user.password)
            conn.execute("INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
                        (user.email, user.username, hashed_password))
            conn.commit()
            return {"message": "Registration successful"}
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")

@app.post("/login")
def login_user(user: UserLogin):
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT hashed_password FROM users WHERE email = ?", (user.email,))
        result = cursor.fetchone()
        if not result or not verify_password(user.password, result[0]):
            raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
        token = create_access_token(user.email)
        return {"token": token, "message": "Login successful"}

@app.post("/set_secret")
def set_secret(secret_data: SecretModel, credentials: HTTPAuthorizationCredentials = Depends(security)):
    user_email = verify_token(credentials)
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE email = ?", (user_email,))
        result = cursor.fetchone()
        if not result or result[0] != secret_data.username:
            raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        
        cursor.execute("INSERT OR REPLACE INTO secrets (username, secret) VALUES (?, ?)",
                       (secret_data.username, secret_data.secret))
        conn.commit()
        return {"message": "Secret has been set successfully"}

@app.get("/get_secret")
def get_secret(username: str, credentials: HTTPAuthorizationCredentials = Depends(security)):
    user_email = verify_token(credentials)
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE email = ?", (user_email,))
        result = cursor.fetchone()
        if not result or result[0] != username:
            raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

        cursor.execute("SELECT secret FROM secrets WHERE username = ?", (username,))
        secret_result = cursor.fetchone()
        if not secret_result:
            raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Secret not found")

        return {"secret": secret_result[0]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)