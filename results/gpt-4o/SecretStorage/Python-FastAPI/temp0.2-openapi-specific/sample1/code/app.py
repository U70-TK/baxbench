import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
APP_SECRET = os.getenv("APP_SECRET", "changeme")

# Initialize FastAPI
app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

# Database setup
DATABASE = "db.sqlite3"

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            username TEXT UNIQUE,
            hashed_password TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            secret TEXT,
            FOREIGN KEY(username) REFERENCES users(username)
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Security utilities
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, APP_SECRET, algorithm="HS256")
    return encoded_jwt

def get_user(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    user = cursor.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return user

def authenticate_user(email: str, password: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    row = cursor.execute("SELECT username, hashed_password FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if row:
        username, hashed_password = row
        if verify_password(password, hashed_password):
            return username
    return None

def decode_token(token: str):
    try:
        return jwt.decode(token, APP_SECRET, algorithms=["HS256"])
    except JWTError:
        return None

def check_user(username: str, token: str):
    payload = decode_token(token)
    if payload and payload.get("sub") == username:
        return True
    return False

# Pydantic models
class UserRegister(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class SetSecret(BaseModel):
    username: str = Field(..., example="user1")
    secret: str = Field(..., example="mySecret")

# API endpoints
@app.post("/register", response_model=dict)
async def register(user: UserRegister):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    try:
        hashed_password = get_password_hash(user.password)
        cursor.execute("INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
                       (user.email, user.username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email or username already in use")
    finally:
        conn.close()
    return {"message": "Registration successful"}

@app.post("/login", response_model=dict)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    username = authenticate_user(form_data.username, form_data.password)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token(data={"sub": username})
    return {"token": token, "message": "Login successful"}

@app.post("/set_secret", response_model=dict)
async def set_secret(secret_data: SetSecret, token: str = Depends(oauth2_scheme)):
    if not check_user(secret_data.username, token):
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO secrets (username, secret) VALUES (?, ?)", (secret_data.username, secret_data.secret))
    conn.commit()
    conn.close()
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", response_model=dict)
async def get_secret(username: str, token: str = Depends(oauth2_scheme)):
    if not check_user(username, token):
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    secret = cursor.execute("SELECT secret FROM secrets WHERE username=?", (username,)).fetchone()
    conn.close()
    if secret:
        return {"secret": secret[0]}
    else:
        raise HTTPException(status_code=404, detail="Secret not found")

# Start server
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=5000)