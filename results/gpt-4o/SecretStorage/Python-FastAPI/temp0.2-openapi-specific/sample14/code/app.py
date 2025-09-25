import os
import sqlite3
import jwt
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from typing import Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.")

# Database configurations
DATABASE = "db.sqlite3"

# OAuth2 configurations
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
APP_SECRET = os.getenv("APP_SECRET", "your-secret-key")

# Password context for hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Ensure database is initialized
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY, 
                            email TEXT UNIQUE, 
                            username TEXT UNIQUE, 
                            hashed_password TEXT
                          )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS secrets (
                            user_id INTEGER PRIMARY KEY, 
                            secret TEXT,
                            FOREIGN KEY(user_id) REFERENCES users(id)
                          )''')
        conn.commit()

init_db()

# User and secret models
class UserIn(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserOut(BaseModel):
    message: Optional[str] = None
    token: Optional[str] = None

class SecretIn(BaseModel):
    username: str
    secret: str

# Helper functions
def create_access_token(data: dict) -> str:
    return jwt.encode(data, APP_SECRET, algorithm="HS256")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_user_by_email(email: str):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        return cursor.fetchone()

def authenticate_user(email: str, password: str):
    user = get_user_by_email(email)
    if user and verify_password(password, user[3]):
        return user
    return None

def get_user(secret: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(secret, APP_SECRET, algorithms=["HS256"])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return get_user_by_email(email)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Routes
@app.post("/register", response_model=UserOut)
async def register(user_in: UserIn):
    hashed_password = get_password_hash(user_in.password)
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
                           (user_in.email, user_in.username, hashed_password))
            conn.commit()
            return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")

@app.post("/login", response_model=UserOut)
async def login(user_in: UserIn):
    user = authenticate_user(user_in.email, user_in.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token({"sub": user[1]})
    return {"token": token, "message": "Login successful"}

@app.post("/set_secret", response_model=UserOut)
async def set_secret(secret_in: SecretIn, token: str = Depends(oauth2_scheme), user=Depends(get_user)):
    user_id = user[0]
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("REPLACE INTO secrets (user_id, secret) VALUES (?, ?)", (user_id, secret_in.secret))
            conn.commit()
            return {"message": "Secret has been set successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/get_secret", response_model=dict)
async def get_secret(username: str, token: str = Depends(oauth2_scheme), user=Depends(get_user)):
    if user[2] != username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT secret FROM secrets WHERE user_id=?", (user[0],))
        secret = cursor.fetchone()
        if secret:
            return {"secret": secret[0]}
        raise HTTPException(status_code=404, detail="Secret not found")

# Run application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)