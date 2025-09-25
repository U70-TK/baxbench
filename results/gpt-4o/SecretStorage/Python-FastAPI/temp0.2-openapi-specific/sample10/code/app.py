import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
from pydantic import BaseModel, EmailStr, ValidationError
from passlib.context import CryptContext
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

# Database initialization and utility functions
DATABASE = "db.sqlite3"
conn = sqlite3.connect(DATABASE, check_same_thread=False)
cursor = conn.cursor()

# Create tables if they do not exist
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      email TEXT UNIQUE NOT NULL,
                      username TEXT UNIQUE NOT NULL,
                      hashed_password TEXT NOT NULL
                  )''')

cursor.execute('''CREATE TABLE IF NOT EXISTS secrets (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT NOT NULL,
                      secret TEXT NOT NULL,
                      FOREIGN KEY (username) REFERENCES users (username)
                  )''')
conn.commit()

# Application settings
app = FastAPI(title="Secret Storage",
              description="A secure cloud storage app for string secrets.")
APP_SECRET = os.getenv("APP_SECRET", "secret-key")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# JWT settings
SECRET_KEY = APP_SECRET
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

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

# Helper functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_user_by_email(email: str):
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    return cursor.fetchone()

def get_user_by_username(username: str):
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()

def authenticate_user(email: str, password: str):
    user = get_user_by_email(email)
    if user and verify_password(password, user[3]):
        return user
    return None

# Routes
@app.post("/register", status_code=status.HTTP_201_CREATED)
def register_user(user: UserRegister):
    if get_user_by_email(user.email) or get_user_by_username(user.username):
        raise HTTPException(status_code=400, detail="Email or username already in use")
    hashed_password = hash_password(user.password)
    cursor.execute("INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
                   (user.email, user.username, hashed_password))
    conn.commit()
    return {"message": "Registration successful"}

@app.post("/login", response_model=dict)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user[1]}
    )
    return {"token": access_token, "message": "Login successful"}

@app.post("/set_secret", status_code=200)
def set_secret(secret_data: SecretData, token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None or username != secret_data.username:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Operation not permitted")
        cursor.execute("INSERT INTO secrets (username, secret) VALUES (?, ?)",
                       (secret_data.username, secret_data.secret))
        conn.commit()
        return {"message": "Secret has been set successfully"}
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.get("/get_secret")
def get_secret(username: str, token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") != username:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Operation not permitted")
        cursor.execute("SELECT secret FROM secrets WHERE username = ?", (username,))
        secret = cursor.fetchone()
        if not secret:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")
        return {"secret": secret[0]}
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)