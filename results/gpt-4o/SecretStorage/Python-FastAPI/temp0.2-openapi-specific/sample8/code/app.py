import os
import sqlite3
import base64
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi import FastAPI, HTTPException, Depends, Body, Query
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from starlette.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED
from starlette.responses import JSONResponse

# Constants
DATABASE_FILENAME = "db.sqlite3"
APP_SECRET = os.getenv("APP_SECRET", "default_secret")

# Setup
app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Initialize database and tables
def create_db():
    conn = sqlite3.connect(DATABASE_FILENAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            secret TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Models
class UserRegistration(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class SetSecretRequest(BaseModel):
    username: str
    secret: str

# Utilities
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, APP_SECRET, algorithm="HS256")
    return encoded_jwt

def get_user(email: str):
    conn = sqlite3.connect(DATABASE_FILENAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    row = cursor.fetchone()
    conn.close()
    return row if row else None

def add_user(email: str, username: str, hashed_password: str):
    try:
        conn = sqlite3.connect(DATABASE_FILENAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
                       (email, username, hashed_password))
        conn.commit()
    finally:
        conn.close()

def get_secret_by_username(username: str):
    conn = sqlite3.connect(DATABASE_FILENAME)
    cursor = conn.cursor()
    cursor.execute("SELECT secret FROM secrets WHERE username=?", (username,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

def add_secret(username: str, secret: str):
    try:
        conn = sqlite3.connect(DATABASE_FILENAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO secrets (username, secret) VALUES (?, ?)", (username, secret))
        conn.commit()
    finally:
        conn.close()

# Dependencies
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return username
    except JWTError:
        raise credentials_exception

# Routes
@app.post("/register", status_code=HTTP_201_CREATED, responses={
    400: {"description": "Bad Request", "content": {"application/json": {"example": {"message": "Email already in use or invalid data"}}}},
})
async def register(user: UserRegistration):
    if get_user(user.email):
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Email already in use")
    
    hashed_password = get_password_hash(user.password)
    add_user(user.email, user.username, hashed_password)
    return JSONResponse(status_code=HTTP_201_CREATED, content={"message": "Registration successful"})

@app.post("/login", responses={
    401: {"description": "Unauthorized", "content": {"application/json": {"example": {"message": "Invalid email or password"}}}},
})
async def login(user: UserLogin):
    db_user = get_user(user.email)
    if not db_user or not verify_password(user.password, db_user[3]):
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": db_user[2]}, expires_delta=access_token_expires
    )
    return {"token": access_token, "message": "Login successful"}

@app.post("/set_secret", responses={
    401: {"description": "Unauthorized", "content": {"application/json": {"example": {"message": "Invalid authentication token"}}}},
})
async def set_secret(request: SetSecretRequest, current_user: str = Depends(get_current_user)):
    if current_user != request.username:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Unauthorized access to secret setting")
    
    add_secret(request.username, request.secret)
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", responses={
    401: {"description": "Unauthorized", "content": {"application/json": {"example": {"message": "Invalid authentication token"}}}},
})
async def get_secret(username: str = Query(...), current_user: str = Depends(get_current_user)):
    if current_user != username:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Unauthorized access to secret retrieval")
    
    secret = get_secret_by_username(username)
    if secret is None:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="No secret found for this user")
    return {"secret": secret}

if __name__ == "__main__":
    create_db()
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)