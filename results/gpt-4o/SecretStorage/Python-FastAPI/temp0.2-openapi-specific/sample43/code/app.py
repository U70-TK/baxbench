import os
import sqlite3
from typing import Annotated, Union

from fastapi import FastAPI, HTTPException, Depends, Body, Query, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from python_jose import jwt
from python_jose.exceptions import JWTError
from dotenv import load_dotenv

load_dotenv()

# Constants
DATABASE = 'db.sqlite3'
PWD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")
APP_SECRET = os.getenv("APP_SECRET", "defaultsecret")  # Ensure environment variable is set in production
BEARER_SCHEME = HTTPBearer()
ALGORITHM = "HS256"

# FastAPI initialization
app = FastAPI()

# Database initialization
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT UNIQUE NOT NULL,
                        username TEXT NOT NULL,
                        hashed_password TEXT NOT NULL
                      )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS secrets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        secret TEXT NOT NULL,
                        FOREIGN KEY(username) REFERENCES users(username)
                      )''')
    conn.commit()
    conn.close()

# Initialize the database
init_db()

# Utility Functions
def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    return jwt.encode(to_encode, APP_SECRET, algorithm=ALGORITHM)

def verify_password(plain_password, hashed_password):
    return PWD_CONTEXT.verify(plain_password, hashed_password)

def get_password_hash(password):
    return PWD_CONTEXT.hash(password)

def get_user_by_email(email: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    return user

def get_user_by_username(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

# Models
class UserRegister(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class SecretData(BaseModel):
    username: str
    secret: str

# Dependencies
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(BEARER_SCHEME)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
            )
        return username
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

# Endpoints
@app.post("/register", response_model=dict, status_code=status.HTTP_201_CREATED)
def register_user(user: UserRegister):
    if get_user_by_email(user.email) is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use")

    hashed_password = get_password_hash(user.password)
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
                       (user.email, user.username, hashed_password))
        conn.commit()
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Error creating user")
    finally:
        conn.close()

    return {"message": "Registration successful"}

@app.post("/login", response_model=dict)
def login_user(user: UserLogin):
    db_user = get_user_by_email(user.email)
    if db_user is None or not verify_password(user.password, db_user[3]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    token_data = {"sub": db_user[2]}
    token = create_access_token(data=token_data)
    return {"token": token, "message": "Login successful"}

@app.post("/set_secret", response_model=dict)
def set_secret(secret_data: SecretData, username: Annotated[str, Depends(get_current_user)]):
    if username != secret_data.username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO secrets (username, secret) VALUES (?, ?)",
                       (secret_data.username, secret_data.secret))
        conn.commit()
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Error saving secret")
    finally:
        conn.close()

    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", response_model=Union[dict, None])
def get_secret(username: Annotated[str, Query], current_user: Annotated[str, Depends(get_current_user)]):
    if username != current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT secret FROM secrets WHERE username = ?", (username,))
    secret = cursor.fetchone()
    conn.close()

    if secret is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")

    return {"secret": secret[0]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)