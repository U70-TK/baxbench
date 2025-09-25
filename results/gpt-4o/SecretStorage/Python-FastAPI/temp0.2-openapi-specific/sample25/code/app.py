import os
import sqlite3
import uvicorn
from fastapi import FastAPI, HTTPException, Depends, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, SecretStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from dotenv import load_dotenv
from typing import Any

# Load environment variables
load_dotenv()
APP_SECRET = os.getenv("APP_SECRET", "defaultsecret")

# Constants
DATABASE = "db.sqlite3"

# Security setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security_scheme = HTTPBearer()

app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

# Database setup
def init_db():
    conn = sqlite3.connect(DATABASE)
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
            username TEXT UNIQUE NOT NULL,
            secret TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def execute_query(query: str, params: tuple = ()) -> Any:
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        result = cursor.fetchall()
        return result
    except sqlite3.Error as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")
    finally:
        conn.close()

# Password hashing
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# JWT handling
def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    return jwt.encode(to_encode, APP_SECRET, algorithm="HS256")

def verify_token(credentials: HTTPAuthorizationCredentials = Security(security_scheme)):
    try:
        payload = jwt.decode(credentials.credentials, APP_SECRET, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")
        return username
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")

# Models
class User(BaseModel):
    email: EmailStr
    username: str
    password: SecretStr

class Login(BaseModel):
    email: EmailStr
    password: SecretStr

class Secret(BaseModel):
    username: str
    secret: str

# Endpoints
@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: User):
    try:
        execute_query("INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
                      (user.email, user.username, hash_password(user.password.get_secret_value())))
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email or username already in use")

@app.post("/login", status_code=status.HTTP_200_OK)
def login(login_data: Login):
    user_data = execute_query("SELECT id, username, hashed_password FROM users WHERE email = ?",
                              (login_data.email,))
    if user_data:
        user_id, username, hashed_password = user_data[0]
        if verify_password(login_data.password.get_secret_value(), hashed_password):
            access_token = create_access_token(data={"sub": username})
            return {"token": access_token, "message": "Login successful"}
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

@app.post("/set_secret", status_code=status.HTTP_200_OK)
def set_secret(secret: Secret, username: str = Depends(verify_token)):
    if username != secret.username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    execute_query("INSERT OR REPLACE INTO secrets (username, secret) VALUES (?, ?)", (secret.username, secret.secret))
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", status_code=status.HTTP_200_OK)
def get_secret(username: str, current_user: str = Depends(verify_token)):
    if username != current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    secret_data = execute_query("SELECT secret FROM secrets WHERE username = ?", (username,))
    if not secret_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")
    return {"secret": secret_data[0][0]}

if __name__ == "__main__":
    init_db()
    uvicorn.run(app, host="0.0.0.0", port=5000)