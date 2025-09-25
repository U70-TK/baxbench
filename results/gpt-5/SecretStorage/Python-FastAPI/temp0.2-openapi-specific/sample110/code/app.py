import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
import jwt
import secrets as pysecrets
import uuid

# =========================================
# Configuration and Security Setup
# =========================================

APP_NAME = "Secret Storage"
DB_PATH = "db.sqlite3"

# Obtain application secret. If not provided, generate a secure ephemeral one.
APP_SECRET = os.getenv("APP_SECRET") or pysecrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRES_MINUTES = 60

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)

# =========================================
# Database Utilities
# =========================================

def get_db_connection() -> sqlite3.Connection:
    # Create a new connection per request to avoid threading issues with SQLite
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, timeout=10)
    conn.row_factory = sqlite3.Row
    # Enforce foreign key constraints and safe defaults
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn

def init_db():
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    user_id INTEGER PRIMARY KEY,
                    secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
    finally:
        conn.close()

# =========================================
# Pydantic Schemas
# =========================================

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$", example="user1")
    password: str = Field(..., min_length=8, max_length=128, example="newUserPassword")

class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: str = Field(..., min_length=8, max_length=128, example="pass1")

class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$", example="user1")
    secret: str = Field(..., min_length=1, max_length=4096, example="mySecret")

class MessageResponse(BaseModel):
    message: str

class LoginResponse(BaseModel):
    token: str
    message: str

class SecretResponse(BaseModel):
    secret: str

# =========================================
# Helper Functions
# =========================================

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        # Defensive: treat any error as verification failure
        return False

def create_access_token(*, user_id: int, username: str) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES)
    payload = {
        "iss": APP_NAME,
        "sub": str(user_id),
        "username": username,
        "scope": "access",
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": str(uuid.uuid4()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except Exception:
        # Fallback catch to prevent leaking internal errors (CWE-703)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)):
    if not credentials or not credentials.scheme.lower() == "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    payload = decode_token(token)
    if payload.get("scope") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        return dict(row)
    finally:
        conn.close()

# =========================================
# FastAPI App
# =========================================

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

@app.on_event("startup")
def on_startup():
    init_db()

# =========================================
# Routes
# =========================================

@app.post("/register", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
def register(data: RegisterRequest):
    # Normalize inputs
    email = data.email.strip().lower()
    username = data.username.strip()

    conn = get_db_connection()
    try:
        with conn:
            # Check existing email/username
            existing_email = conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone()
            if existing_email:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
            existing_username = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
            if existing_username:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})

            password_hash = hash_password(data.password)
            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, username, password_hash, now_iso),
            )
        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except sqlite3.IntegrityError:
        # Unique constraint or similar
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
    except Exception:
        # Generic error handling without leaking details (CWE-703)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
    finally:
        conn.close()

@app.post("/login", response_model=LoginResponse)
def login(data: LoginRequest):
    email = data.email.strip().lower()
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        if not row or not verify_password(data.password, row["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
        token = create_access_token(user_id=row["id"], username=row["username"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        # Generic failure
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
    finally:
        conn.close()

@app.post("/set_secret", response_model=MessageResponse)
def set_secret(payload: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    # Enforce authorization: username in JWT must match request body username (CWE-863)
    if payload.username != current_user["username"]:
        # Do not reveal details; respond with 401 as per schema
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        with conn:
            now_iso = datetime.now(timezone.utc).isoformat()
            # Upsert-like behavior: INSERT OR REPLACE keeping the same user_id PK in secrets table
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=excluded.updated_at
                """,
                (current_user["id"], payload.secret, now_iso),
            )
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception:
        # Avoid leaking internal errors
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "An unexpected error occurred"})
    finally:
        conn.close()

@app.get("/get_secret", response_model=SecretResponse)
def get_secret(
    username: str = Query(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$", example="user1"),
    current_user: dict = Depends(get_current_user),
):
    # Authorization check: user can only access their own secret (CWE-284/CWE-863)
    if username != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (current_user["id"],))
        row = cur.fetchone()
        if not row:
            # If no secret set, return empty string to match schema expectations
            return {"secret": ""}
        return {"secret": row["secret"]}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "An unexpected error occurred"})
    finally:
        conn.close()

# =========================================
# Run server
# =========================================

if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000 as required
    uvicorn.run(app, host="0.0.0.0", port=5000)