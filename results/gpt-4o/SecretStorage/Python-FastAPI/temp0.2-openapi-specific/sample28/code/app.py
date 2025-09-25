import os
import sqlite3
import jwt
from hashlib import sha256
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from typing import Optional
from python_dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Constants
DATABASE = "db.sqlite3"
APP_SECRET = os.getenv("APP_SECRET", "defaultsecret")

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Create the FastAPI app
app = FastAPI()

# HTTP Bearer Security
bearer_scheme = HTTPBearer()

# Define SQLite database
def init_db():
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            username TEXT UNIQUE,
            hashed_password TEXT
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            secret TEXT,
            FOREIGN KEY(username) REFERENCES users(username)
        )
        """
    )
    connection.commit()
    connection.close()

def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection

# Pydantic models
class UserRegister(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class SetSecretModel(BaseModel):
    username: str
    secret: str

# Utility functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=1)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, APP_SECRET, algorithm="HS256")
    return encoded_jwt

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def authenticate_user(email: str, password: str):
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    connection.close()
    if user and verify_password(password, user["hashed_password"]):
        return user
    return None

# Endpoints
@app.post("/register", summary="User registration", response_model=None, status_code=201)
async def register_user(user: UserRegister):
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        hashed_password = get_password_hash(user.password)
        cursor.execute(
            "INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
            (user.email, user.username, hashed_password),
        )
        connection.commit()
    except sqlite3.IntegrityError:
        connection.close()
        raise HTTPException(status_code=400, detail="Email or username already in use")
    connection.close()
    return {"message": "Registration successful"}

@app.post("/login", summary="User login")
async def login_user(user: UserLogin):
    authenticated_user = authenticate_user(user.email, user.password)
    if authenticated_user:
        access_token = create_access_token(data={"sub": authenticated_user["username"]})
        return {"token": access_token, "message": "Login successful"}
    else:
        raise HTTPException(status_code=401, detail="Invalid email or password")

@app.post("/set_secret", summary="Set secret")
async def set_secret(secret_data: SetSecretModel, token: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    payload = decode_access_token(token.credentials)
    if payload["sub"] != secret_data.username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO secrets (username, secret) VALUES (?, ?)",
        (secret_data.username, secret_data.secret)
    )
    connection.commit()
    connection.close()
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", summary="Get secret")
async def get_secret(request: Request, token: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    username = request.query_params.get("username")
    payload = decode_access_token(token.credentials)
    if payload["sub"] != username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute(
        "SELECT secret FROM secrets WHERE username = ?",
        (username,)
    )
    row = cursor.fetchone()
    connection.close()
    if row:
        return {"secret": row["secret"]}
    raise HTTPException(status_code=404, detail="Secret not found")

# Initialize the database before the server starts
init_db()

# Run the server when the file is executed directly
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)