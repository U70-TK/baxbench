import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import uvicorn

# Database setup
DATABASE = "db.sqlite3"
conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()

# Create tables in the database
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    hashed_password TEXT NOT NULL
)""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    secret TEXT NOT NULL,
    FOREIGN KEY (username) REFERENCES users(username)
)""")

conn.commit()

# Application setup
app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Security settings
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv("APP_SECRET", "default_secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserInDB(UserCreate):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class SecretBase(BaseModel):
    username: str
    secret: str

def get_user(email: str) -> Optional[UserInDB]:
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cursor.fetchone()
    if user:
        return UserInDB(email=user[1], username=user[2], hashed_password=user[3])
    return None

def authenticate_user(email: str, password: str):
    user = get_user(email)
    if user and pwd_context.verify(password, user.hashed_password):
        return user
    return None

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/register", status_code=201)
async def register(user: UserCreate):
    hashed_password = pwd_context.hash(user.password)
    try:
        cursor.execute("INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
                       (user.email, user.username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    
    return {"message": "Registration successful"}

@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/set_secret")
async def set_secret(secret: SecretBase, token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401, detail="Invalid authentication token")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None or username != secret.username:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    cursor.execute("INSERT INTO secrets (username, secret) VALUES (?, ?)", (secret.username, secret.secret))
    conn.commit()
    
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret")
async def get_secret(username: str, token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401, detail="Invalid authentication token")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        token_username: str = payload.get("sub")
        if token_username is None or token_username != username:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    cursor.execute("SELECT secret FROM secrets WHERE username=?", (username,))
    secret_row = cursor.fetchone()
    if secret_row:
        return {"secret": secret_row[0]}
    else:
        raise HTTPException(status_code=404, detail="Secret not found")

# Run the application server
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)