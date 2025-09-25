import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends, Header, Body, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import jwt
from typing import Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Constants and configurations
DATABASE_FILE = 'db.sqlite3'
APP_SECRET = os.getenv('APP_SECRET', 'your_secret_key_here')
ALGORITHM = "HS256"

# Initialize FastAPI app
app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

# Configure password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Use HTTPBearer for token authentication
security = HTTPBearer()

# Database initialization
def init_db():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT NOT NULL UNIQUE,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS secrets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        secret TEXT NOT NULL,
                        FOREIGN KEY(username) REFERENCES users(username))''')
    conn.commit()
    conn.close()

init_db()

# Models
class RegisterModel(BaseModel):
    email: EmailStr
    username: str
    password: str

class LoginModel(BaseModel):
    email: EmailStr
    password: str

class SecretModel(BaseModel):
    username: str
    secret: str

# Helper functions
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(email: str):
    payload = {"sub": email}
    return jwt.encode(payload, APP_SECRET, algorithm=ALGORITHM)

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.PyJWTError:
        return None

def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    return conn, conn.cursor()

# Routes
@app.post('/register', status_code=status.HTTP_201_CREATED)
def register(user: RegisterModel):
    conn, cursor = get_db_connection()
    hashed_password = get_password_hash(user.password)
    
    try:
        cursor.execute('INSERT INTO users (email, username, password) VALUES (?, ?, ?)',
                       (user.email, user.username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")
    
    conn.close()
    return {"message": "Registration successful"}

@app.post('/login', response_model=dict)
def login(user: LoginModel):
    conn, cursor = get_db_connection()
    cursor.execute('SELECT password FROM users WHERE email=?', (user.email,))
    row = cursor.fetchone()
    conn.close()
    
    if row and verify_password(user.password, row[0]):
        token = create_access_token(user.email)
        return {"token": token, "message": "Login successful"}
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

@app.post('/set_secret', response_model=dict)
def set_secret(secret_data: SecretModel, credentials: HTTPAuthorizationCredentials = Depends(security)):
    user_email = decode_access_token(credentials.credentials)
    if not user_email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    
    conn, cursor = get_db_connection()
    cursor.execute('SELECT username FROM users WHERE email=?', (user_email,))
    row = cursor.fetchone()
    
    if row and row[0] == secret_data.username:
        cursor.execute('INSERT INTO secrets (username, secret) VALUES (?, ?)', (secret_data.username, secret_data.secret))
        conn.commit()
        conn.close()
        return {"message": "Secret has been set successfully"}
    else:
        conn.close()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

@app.get('/get_secret', response_model=dict)
def get_secret(username: str, credentials: HTTPAuthorizationCredentials = Depends(security)):
    user_email = decode_access_token(credentials.credentials)
    if not user_email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    
    conn, cursor = get_db_connection()
    cursor.execute('SELECT username FROM users WHERE email=?', (user_email,))
    row = cursor.fetchone()
    
    if row and row[0] == username:
        cursor.execute('SELECT secret FROM secrets WHERE username=?', (username,))
        secret_row = cursor.fetchone()
        conn.close()
        
        if secret_row:
            return {"secret": secret_row[0]}
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")
    else:
        conn.close()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

# Start the server
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=5000)