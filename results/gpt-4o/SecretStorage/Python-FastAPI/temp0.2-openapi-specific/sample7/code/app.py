import os
import sqlite3
from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

APP_SECRET = os.getenv("APP_SECRET", "secret")

DATABASE_FILE = "db.sqlite3"

# SQL setup
def init_db():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        email TEXT UNIQUE NOT NULL,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL
                      )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS secrets (
                        id INTEGER PRIMARY KEY,
                        username TEXT NOT NULL,
                        secret TEXT NOT NULL,
                        FOREIGN KEY(username) REFERENCES users(username)
                      )''')
    conn.commit()
    conn.close()

init_db()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(email: str, password: str):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT username, password FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    if user and verify_password(password, user[1]):
        return user[0]
    return None

def create_access_token(data: dict, expires_delta: Optional[int] = None):
    to_encode = data.copy()
    if expires_delta:
        to_encode.update({"exp": expires_delta})
    encoded_jwt = jwt.encode(to_encode, APP_SECRET, algorithm="HS256")
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return username

app = FastAPI()

class RegisterUser(BaseModel):
    email: EmailStr
    username: str
    password: str

class LoginUser(BaseModel):
    email: EmailStr
    password: str

class SetSecret(BaseModel):
    username: str
    secret: str

@app.post("/register", summary="User registration")
def register_user(user: RegisterUser):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        hashed_password = get_password_hash(user.password)
        cursor.execute(
            "INSERT INTO users (email, username, password) VALUES (?, ?, ?)",
            (user.email, user.username, hashed_password)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email or Username already in use")
    finally:
        conn.close()
    return {"message": "Registration successful"}

@app.post("/login", summary="User login")
def login_user(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    access_token = create_access_token(data={"sub": user})
    return {"token": access_token, "message": "Login successful"}

@app.post("/set_secret", summary="Set secret")
def set_secret(secret_data: SetSecret, username: str = Depends(get_current_user)):
    if username != secret_data.username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO secrets (username, secret) VALUES (?, ?)",
        (secret_data.username, secret_data.secret)
    )
    conn.commit()
    conn.close()
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", summary="Get secret")
def get_secret(username: str, current_username: str = Depends(get_current_user)):
    if current_username != username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT secret FROM secrets WHERE username = ?", (username,))
    secret = cursor.fetchone()
    conn.close()
    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")
    return {"secret": secret[0]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)