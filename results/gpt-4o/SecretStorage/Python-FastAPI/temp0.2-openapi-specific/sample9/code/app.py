import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr
from typing import Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
APP_SECRET = os.getenv("APP_SECRET")

# Initialize FastAPI app
app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

# Security settings
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# JWT settings
ALGORITHM = "HS256"

# SQLite Database setup
DATABASE = 'db.sqlite3'
conn = sqlite3.connect(DATABASE, check_same_thread=False)
cursor = conn.cursor()

def init_db():
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
        user_id INTEGER,
        secret TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """)
    conn.commit()

init_db()

class UserIn(BaseModel):
    email: EmailStr
    username: str
    password: str

class TokenData(BaseModel):
    username: Optional[str] = None

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def hash_password(password):
    return pwd_context.hash(password)

def authenticate_user(email: str, password: str):
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user_row = cursor.fetchone()
    if user_row is None:
        return None
    user_id, email, username, hashed_password = user_row
    if not verify_password(password, hashed_password):
        return None
    return {"id": user_id, "email": email, "username": username}

def create_access_token(data: dict):
    return jwt.encode(data, APP_SECRET, algorithm=ALGORITHM)

async def get_current_user(token: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication token",
    )
    try:
        payload = jwt.decode(token.credentials, APP_SECRET, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return username
    except JWTError:
        raise credentials_exception

@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user: UserIn):
    hashed_password = hash_password(user.password)
    try:
        cursor.execute("INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)", 
                       (user.email, user.username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")
    return {"message": "Registration successful"}

@app.post("/login", status_code=status.HTTP_200_OK)
async def login(user: UserIn):
    user_obj = authenticate_user(user.email, user.password)
    if not user_obj:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    access_token = create_access_token(data={"sub": user_obj['username']})
    return {"token": access_token, "message": "Login successful"}

@app.post("/set_secret", status_code=status.HTTP_200_OK)
async def set_secret(request: Request, token: HTTPAuthorizationCredentials = Depends(security)):
    data = await request.json()
    username = await get_current_user(token)
    if username != data.get("username"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    cursor.execute("SELECT id FROM users WHERE username=?", (username,))
    user_id = cursor.fetchone()[0]
    cursor.execute("INSERT INTO secrets (user_id, secret) VALUES (?, ?)", (user_id, data.get("secret")))
    conn.commit()
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", status_code=status.HTTP_200_OK)
async def get_secret(username: str, token: HTTPAuthorizationCredentials = Depends(security)):
    auth_username = await get_current_user(token)
    if auth_username != username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    cursor.execute("SELECT secret FROM secrets JOIN users ON users.id = secrets.user_id WHERE users.username=?", (username,))
    secret_row = cursor.fetchone()
    if secret_row:
        return {"secret": secret_row[0]}
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")