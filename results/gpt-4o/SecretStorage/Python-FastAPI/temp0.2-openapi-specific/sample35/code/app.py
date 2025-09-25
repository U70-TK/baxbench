import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta

# Settings
DATABASE_URL = "db.sqlite3"
SECRET_KEY = os.getenv("APP_SECRET", "CHANGE_THIS_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Application setup
app = FastAPI()

# Initialize password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security scheme
security = HTTPBearer()

# Database setup
def init_db():
    conn = sqlite3.connect(DATABASE_URL)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        username TEXT UNIQUE,
        hashed_password TEXT
    )''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS secrets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        secret TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()

# Pydantic models
class UserRegister(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class SecretModel(BaseModel):
    username: str
    secret: str

# Functions for security
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(email: str):
    conn = sqlite3.connect(DATABASE_URL)
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, username, hashed_password FROM users WHERE email=?", (email,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "email": row[1], "username": row[2], "hashed_password": row[3]}
    return None

def get_user_by_username(username: str):
    conn = sqlite3.connect(DATABASE_URL)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]
    return None

def store_secret(user_id: int, secret: str):
    conn = sqlite3.connect(DATABASE_URL)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO secrets (user_id, secret) VALUES (?, ?)", (user_id, secret))
    conn.commit()
    conn.close()

def retrieve_secret(user_id: int):
    conn = sqlite3.connect(DATABASE_URL)
    cursor = conn.cursor()
    cursor.execute("SELECT secret FROM secrets WHERE user_id=?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]
    return None

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        return get_user(email)
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

# API Endpoints
@app.post("/register", tags=["Authentication"])
async def register(user: UserRegister):
    # Check if user already exists
    if get_user(user.email):
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")

    # Hash the password
    hashed_password = get_password_hash(user.password)

    # Insert into database
    conn = sqlite3.connect(DATABASE_URL)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)", 
                   (user.email, user.username, hashed_password))
    conn.commit()
    conn.close()

    return {"message": "Registration successful"}

@app.post("/login", tags=["Authentication"])
async def login(user: UserLogin):
    db_user = get_user(user.email)
    if not db_user or not verify_password(user.password, db_user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": db_user["email"]}, expires_delta=access_token_expires
    )
    return {"token": access_token, "message": "Login successful"}

@app.post("/set_secret", tags=["Secrets"])
async def set_secret(secret_data: SecretModel, current_user: dict = Depends(get_current_user)):
    user_id = get_user_by_username(secret_data.username)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    store_secret(user_id, secret_data.secret)
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", tags=["Secrets"])
async def get_secret(username: str, current_user: dict = Depends(get_current_user)):
    user_id = get_user_by_username(username)
    if user_id is None or current_user["username"] != username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    secret = retrieve_secret(user_id)
    if secret is None:
        raise HTTPException(status_code=404, detail="Secret not found")
    
    return {"secret": secret}

# Initialize the database
init_db()

# Start the server
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)