import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from typing import Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
APP_SECRET = os.getenv("APP_SECRET")

# Database configurations
DATABASE_NAME = 'db.sqlite3'

# Initialize FastAPI app
app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

# Cryptography context for hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 password flow
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Database setup
def init_db():
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            secret TEXT NOT NULL
        )''')
    conn.commit()
    conn.close()

# Initialize database
init_db()

# Models
class UserRegister(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class SetSecret(BaseModel):
    username: str
    secret: str

# Authentication and Authorization
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(email: str, password: str):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cursor.fetchone()
    conn.close()
    if user and verify_password(password, user[3]):
        return user
    return None

def create_access_token(data: dict, expires_delta: Optional[int] = None):
    to_encode = data.copy()
    token = jwt.encode(to_encode, APP_SECRET, algorithm="HS256")
    return token

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        return email
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

# Routes
@app.post("/register", tags=["Authentication"])
def register(user: UserRegister):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    try:
        hashed_password = get_password_hash(user.password)
        cursor.execute("INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)", 
                       (user.email, user.username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email or username already in use")
    finally:
        conn.close()
    return {"message": "Registration successful"}

@app.post("/login", tags=["Authentication"])
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    access_token = create_access_token(data={"sub": user[1]})
    return {"token": access_token, "message": "Login successful"}

@app.post("/set_secret")
def set_secret(secret_data: SetSecret, token: str = Depends(oauth2_scheme)):
    user_email = get_current_user(token)
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?", (user_email,))
    user = cursor.fetchone()
    if user is None or user[2] != secret_data.username:
        raise HTTPException(status_code=401, detail="Unauthorized")
    cursor.execute("INSERT INTO secrets (username, secret) VALUES (?, ?)", 
                   (secret_data.username, secret_data.secret))
    conn.commit()
    conn.close()
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret")
def get_secret(username: str, token: str = Depends(oauth2_scheme)):
    user_email = get_current_user(token)
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?", (user_email,))
    user = cursor.fetchone()
    if user is None or user[2] != username:
        raise HTTPException(status_code=401, detail="Unauthorized")
    cursor.execute("SELECT secret FROM secrets WHERE username=?", (username,))
    secret_record = cursor.fetchone()
    conn.close()
    if secret_record is None:
        raise HTTPException(status_code=404, detail="Secret not found")
    return {"secret": secret_record[0]}

# Start server
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)