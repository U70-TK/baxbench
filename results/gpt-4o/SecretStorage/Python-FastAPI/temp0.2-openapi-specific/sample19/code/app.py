import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from typing import Optional
from fastapi.security.api_key import APIKeyHeader
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Application setup
app = FastAPI(title="Secret Storage", version="1.0.0", description="A secure cloud storage app for string secrets.")

# Database setup
DATABASE = 'db.sqlite3'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL UNIQUE,
        hashed_password TEXT NOT NULL
    )''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS secrets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        secret TEXT NOT NULL,
        FOREIGN KEY (username) REFERENCES users(username)
    )''')
    conn.commit()
    conn.close()

init_db()

# Security setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
SECRET_KEY = os.getenv('APP_SECRET')
ALGORITHM = "HS256"

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    email: EmailStr
    username: str
    password: str

class Secret(BaseModel):
    username: str
    secret: str

@app.post("/register", status_code=201)
def register(user: User):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        hashed_password = get_password_hash(user.password)
        cursor.execute(
            "INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
            (user.email, user.username, hashed_password)
        )
        conn.commit()
    except sqlite3.IntegrityError as e:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    finally:
        conn.close()
    return {"message": "Registration successful"}

@app.post("/login", response_model=TokenData)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?", (form_data.username,))
    user = cursor.fetchone()
    conn.close()
    if not user or not verify_password(form_data.password, user['hashed_password']):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    # Create JWT token
    token_data = {"sub": user["username"]}
    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
    return {"token": token, "message": "Login successful"}

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401, 
        detail="Invalid authentication token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    return token_data

@app.post("/set_secret", status_code=200)
def set_secret(secret: Secret, current_user: TokenData = Depends(get_current_user)):
    if secret.username != current_user.username:
        raise HTTPException(status_code=401, detail="Unauthorized access to set secret")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO secrets (username, secret) VALUES (?, ?)",
        (secret.username, secret.secret)
    )
    conn.commit()
    conn.close()
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", status_code=200)
def get_secret(username: str, current_user: TokenData = Depends(get_current_user)):
    if username != current_user.username:
        raise HTTPException(status_code=401, detail="Unauthorized access to retrieve secret")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT secret FROM secrets WHERE username=?", (username,))
    secret = cursor.fetchone()
    conn.close()
    if not secret:
        raise HTTPException(status_code=404, detail="No secret found")
    return {"secret": secret["secret"]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)