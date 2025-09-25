import os
import sqlite3
from typing import Optional

import jwt
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from starlette.middleware.cors import CORSMiddleware
from starlette.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_200_OK, HTTP_401_UNAUTHORIZED

# Load application secret
APP_SECRET = os.getenv("APP_SECRET", "supersecret")

# Initialize FastAPI app
app = FastAPI(title="Secret Storage")

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup SQLite database
DATABASE_NAME = "db.sqlite3"
conn = sqlite3.connect(DATABASE_NAME)
c = conn.cursor()

# Create tables
c.execute(
    """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL
    )
    """
)
c.execute(
    """
    CREATE TABLE IF NOT EXISTS secrets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        secret TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """
)
conn.commit()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Models
class UserRegister(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class SetSecretRequest(BaseModel):
    username: str
    secret: str

# Security utilities
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_jwt(email: str) -> str:
    return jwt.encode({"sub": email}, APP_SECRET, algorithm="HS256")

def decode_jwt(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        return payload.get("sub")
    except jwt.PyJWTError:
        return None

# Routes
@app.post("/register", status_code=HTTP_201_CREATED)
async def register(user: UserRegister):
    try:
        hashed_password = hash_password(user.password)
        with sqlite3.connect(DATABASE_NAME) as db:
            c = db.cursor()
            c.execute("INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
                      (user.email, user.username, hashed_password))
            db.commit()
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Email or username already in use")

@app.post("/login", response_model=dict, status_code=HTTP_200_OK)
async def login(credentials: UserLogin):
    with sqlite3.connect(DATABASE_NAME) as db:
        c = db.cursor()
        c.execute("SELECT hashed_password FROM users WHERE email = ?", (credentials.email,))
        user = c.fetchone()
        if user and verify_password(credentials.password, user[0]):
            token = create_jwt(credentials.email)
            return {"token": token, "message": "Login successful"}
    raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

@app.post("/set_secret", status_code=HTTP_200_OK)
async def set_secret(request: SetSecretRequest, token: str = Depends(oauth2_scheme)):
    email = decode_jwt(token)
    if not email:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    with sqlite3.connect(DATABASE_NAME) as db:
        c = db.cursor()
        c.execute("SELECT id FROM users WHERE email = ? AND username = ?", (email, request.username))
        user = c.fetchone()
        if user:
            user_id = user[0]
            c.execute("INSERT INTO secrets (user_id, secret) VALUES (?, ?)", (user_id, request.secret))
            db.commit()
            return {"message": "Secret has been set successfully"}
    raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

@app.get("/get_secret", status_code=HTTP_200_OK)
async def get_secret(username: str, token: str = Depends(oauth2_scheme)):
    email = decode_jwt(token)
    if not email:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    with sqlite3.connect(DATABASE_NAME) as db:
        c = db.cursor()
        c.execute("SELECT u.id FROM users u WHERE u.email = ? AND u.username = ?", (email, username))
        user = c.fetchone()
        if user:
            user_id = user[0]
            c.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
            secret_row = c.fetchone()
            if secret_row:
                return {"secret": secret_row[0]}
    raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)