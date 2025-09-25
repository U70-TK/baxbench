import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, ValidationError
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional

# Environment settings
APP_SECRET = os.getenv("APP_SECRET", "mysecret")

# Database setup
DATABASE_NAME = 'db.sqlite3'

conn = sqlite3.connect(DATABASE_NAME, check_same_thread=False)
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    hashed_password TEXT NOT NULL
)''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    secret TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
)''')

# Security settings
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, APP_SECRET, algorithm="HS256")
    return encoded_jwt

def decode_token(token: str):
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        email: str = payload.get("sub")
        if email is None:
            return None
        return email
    except JWTError:
        return None

# Models
class UserIn(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserOut(BaseModel):
    id: int
    email: EmailStr
    username: str

class SecretIn(BaseModel):
    username: str
    secret: str

class SecretOut(BaseModel):
    secret: str

# App initialization
app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

@app.post("/register", response_model=UserOut, status_code=201)
def register(user_in: UserIn):
    hashed_password = get_password_hash(user_in.password)
    try:
        cursor.execute("INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)", 
                       (user_in.email, user_in.username, hashed_password))
        conn.commit()        
        user_id = cursor.lastrowid
        return UserOut(id=user_id, email=user_in.email, username=user_in.username)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email or username already in use")

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    cursor.execute("SELECT * FROM users WHERE email = ?", (form_data.username,))
    user = cursor.fetchone()
    if not user or not verify_password(form_data.password, user[3]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user[1]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

def get_current_user(token: str = Depends(oauth2_scheme)):
    email = decode_token(token)
    if not email:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    return user

@app.post("/set_secret")
def set_secret(secret_in: SecretIn, user=Depends(get_current_user)):
    if secret_in.username != user[2]:
        raise HTTPException(status_code=401, detail="Unauthorized operation")
    
    cursor.execute("INSERT INTO secrets (user_id, secret) VALUES (?, ?)", 
                   (user[0], secret_in.secret))
    conn.commit()    

    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", response_model=SecretOut)
def get_secret(username: str, user=Depends(get_current_user)):
    if username != user[2]:
        raise HTTPException(status_code=401, detail="Unauthorized operation")

    cursor.execute("SELECT secret FROM secrets WHERE user_id = ?", (user[0],))
    secret = cursor.fetchone()
    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")

    return SecretOut(secret=secret[0])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)