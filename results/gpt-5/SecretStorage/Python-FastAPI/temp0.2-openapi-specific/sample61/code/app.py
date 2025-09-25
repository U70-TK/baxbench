import os
import sqlite3
import threading
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt  # PyJWT
from fastapi import FastAPI, HTTPException, status, Request, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
import uvicorn

# Application configuration
APP_SECRET = os.getenv("APP_SECRET") or pysecrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Initialize FastAPI
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Custom exception handler to match expected error response shape: {"message": "..."}
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    message = exc.detail if isinstance(exc.detail, str) else "An error occurred"
    headers = exc.headers or {}
    return JSONResponse(status_code=exc.status_code, content={"message": message}, headers=headers)

# Password hashing context (secure, no external dependencies required)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# SQLite setup
DB_PATH = "db.sqlite3"
db_lock = threading.Lock()
conn = sqlite3.connect(DB_PATH, check_same_thread=False, detect_types=sqlite3.PARSE_DECLTYPES)
conn.row_factory = sqlite3.Row

def init_db():
    with db_lock:
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER UNIQUE NOT NULL,
                    secret TEXT,
                    updated_at TIMESTAMP NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
            conn.commit()
        except Exception:
            # Rollback on initialization error to avoid partial schema creation
            conn.rollback()
            raise

init_db()

# Utility functions for DB access (using parameterized queries to prevent SQL injection - CWE-89)
def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    with db_lock:
        cur = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
        return cur.fetchone()

def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    with db_lock:
        cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cur.fetchone()

def create_user(email: str, username: str, password_hash: str) -> int:
    with db_lock:
        try:
            now = datetime.now(timezone.utc)
            cur = conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, username, password_hash, now),
            )
            conn.commit()
            return cur.lastrowid
        except sqlite3.IntegrityError:
            conn.rollback()
            # Email or username already in use
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use or invalid data",
            )
        except Exception:
            conn.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error",
            )

def upsert_secret(user_id: int, secret_text: str) -> None:
    with db_lock:
        try:
            now = datetime.now(timezone.utc)
            existing = conn.execute("SELECT id FROM secrets WHERE user_id = ?", (user_id,)).fetchone()
            if existing:
                conn.execute(
                    "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
                    (secret_text, now, user_id),
                )
            else:
                conn.execute(
                    "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
                    (user_id, secret_text, now),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error",
            )

def fetch_secret(user_id: int) -> str:
    with db_lock:
        try:
            row = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,)).fetchone()
            return row["secret"] if row and row["secret"] is not None else ""
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error",
            )

# Security utilities
def create_access_token(user: sqlite3.Row) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user["username"],
        "uid": user["id"],
        "email": user["email"],
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "type": "access",
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user(request: Request) -> sqlite3.Row:
    auth_header = request.headers.get("Authorization") or ""
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = parts[1]
    payload = decode_token(token)
    uid = payload.get("uid")
    if uid is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = None
    try:
        with db_lock:
            user = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )
    if not user:
        # Token references a non-existent user
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

# Pydantic models for request bodies
class RegisterRequest(BaseModel):
    email: EmailStr = Field(example="newuser@example.com")
    username: str = Field(min_length=1, max_length=64, example="user1")
    password: str = Field(min_length=8, max_length=128, example="newUserPassword")

class LoginRequest(BaseModel):
    email: EmailStr = Field(example="user@example.com")
    password: str = Field(min_length=8, max_length=128, example="mySecretPassword")

class SetSecretRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64, example="user1")
    secret: str = Field(min_length=0, max_length=4096, example="mySecret")

# Routes

@app.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    summary="User registration",
    description="Register a new user with email, username and password.",
    tags=["Authentication"],
)
async def register(payload: RegisterRequest):
    # normalize email
    email_norm = payload.email.lower()
    username = payload.username.strip()
    if not username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )
    # Check if email or username already exists
    existing_email = get_user_by_email(email_norm)
    existing_username = get_user_by_username(username)
    if existing_email or existing_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )
    # Hash password securely (CWE-522 mitigation)
    try:
        password_hash = pwd_context.hash(payload.password)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )
    create_user(email_norm, username, password_hash)
    return {"message": "Registration successful"}

@app.post(
    "/login",
    status_code=status.HTTP_200_OK,
    summary="User login",
    description="Authenticate a user with email and password.",
    tags=["Authentication"],
)
async def login(payload: LoginRequest):
    email_norm = payload.email.lower()
    user = get_user_by_email(email_norm)
    if not user:
        # Avoid user enumeration; generic message
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    # Verify password in constant-time
    try:
        if not pwd_context.verify(payload.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )
    token = create_access_token(user)
    return {"token": token, "message": "Login successful"}

@app.post(
    "/set_secret",
    status_code=status.HTTP_200_OK,
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
async def set_secret(payload: SetSecretRequest, current_user: sqlite3.Row = Depends(get_current_user)):
    # Authorization check (CWE-284, CWE-863 mitigation): ensure the authenticated user matches the target username
    if payload.username != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Store the secret securely
    upsert_secret(current_user["id"], payload.secret)
    return {"message": "Secret has been set successfully"}

@app.get(
    "/get_secret",
    status_code=status.HTTP_200_OK,
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
async def get_secret(username: str = Query(..., example="user1"), current_user: sqlite3.Row = Depends(get_current_user)):
    # Authorization check: only allow the authenticated user to access their own secret
    if username != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    secret_text = fetch_secret(current_user["id"])
    return {"secret": secret_text}

if __name__ == "__main__":
    # Run the server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)