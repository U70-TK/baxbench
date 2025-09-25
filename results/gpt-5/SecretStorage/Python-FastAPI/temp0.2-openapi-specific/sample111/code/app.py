import os
import re
import sqlite3
import time
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Body, Query, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, ValidationError, field_validator
from passlib.hash import pbkdf2_sha256
import jwt

# ===========================
# Configuration and Constants
# ===========================
DB_PATH = "db.sqlite3"
APP_SECRET = os.environ.get("APP_SECRET") or secrets.token_urlsafe(32)
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,30}$")

# ===========================
# FastAPI App
# ===========================
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# ===========================
# Utility Functions
# ===========================
def _connect_db(retries: int = 3, delay: float = 0.1) -> sqlite3.Connection:
    """
    Connect to the SQLite database with retries and safe defaults.
    """
    last_exc = None
    for _ in range(retries):
        try:
            conn = sqlite3.connect(DB_PATH, timeout=5.0, isolation_level=None, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            return conn
        except sqlite3.OperationalError as e:
            last_exc = e
            time.sleep(delay)
    raise last_exc if last_exc else sqlite3.OperationalError("Failed to connect to database")

def _execute_db(query: str, params: Tuple = (), commit: bool = False, retries: int = 3, delay: float = 0.1):
    """
    Execute a parameterized SQL query safely with retry on database locks.
    """
    if not isinstance(params, (tuple, list)):
        raise ValueError("Params must be a tuple or list")
    last_exc = None
    for _ in range(retries):
        try:
            with _connect_db() as conn:
                cur = conn.execute(query, params)
                if commit:
                    conn.commit()
                return cur
        except sqlite3.OperationalError as e:
            # Handle transient errors like "database is locked"
            last_exc = e
            time.sleep(delay)
    raise last_exc if last_exc else sqlite3.OperationalError("Database operation failed")

def init_db():
    """
    Initialize database schema.
    """
    _execute_db(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """,
        (),
        commit=True,
    )
    _execute_db(
        """
        CREATE TABLE IF NOT EXISTS secrets (
            user_id INTEGER PRIMARY KEY,
            secret TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """,
        (),
        commit=True,
    )

def hash_password(password: str) -> str:
    return pbkdf2_sha256.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, password_hash)
    except Exception:
        # In case of any unexpected error from the hash library, treat as failure
        return False

def create_access_token(username: str) -> str:
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALG)
    return token

def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALG])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    cur = _execute_db("SELECT * FROM users WHERE email = ?", (email,))
    return cur.fetchone()

def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    cur = _execute_db("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()

def create_user(email: str, username: str, password: str) -> bool:
    if get_user_by_email(email) is not None:
        return False
    if get_user_by_username(username) is not None:
        return False
    pwd_hash = hash_password(password)
    try:
        _execute_db(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, pwd_hash, datetime.utcnow().isoformat() + "Z"),
            commit=True,
        )
        return True
    except sqlite3.IntegrityError:
        # Unique constraint violation or similar
        return False

def set_secret_for_user(username: str, secret: str) -> bool:
    user = get_user_by_username(username)
    if not user:
        return False
    user_id = user["id"]
    now = datetime.utcnow().isoformat() + "Z"
    cur = _execute_db("SELECT user_id FROM secrets WHERE user_id = ?", (user_id,))
    existing = cur.fetchone()
    if existing:
        _execute_db(
            "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
            (secret, now, user_id),
            commit=True,
        )
    else:
        _execute_db(
            "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
            (user_id, secret, now),
            commit=True,
        )
    return True

def get_secret_for_user(username: str) -> Optional[str]:
    user = get_user_by_username(username)
    if not user:
        return None
    user_id = user["id"]
    cur = _execute_db("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if row is None:
        return ""
    return row["secret"] or ""

# ===========================
# Schemas
# ===========================
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=30)
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not USERNAME_REGEX.fullmatch(v):
            raise ValueError("Username must be 3-30 characters and only contain letters, numbers, and underscores")
        return v

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=128)

class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=30)
    secret: str = Field(..., min_length=1, max_length=10000)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not USERNAME_REGEX.fullmatch(v):
            raise ValueError("Invalid username format")
        return v

class MessageResponse(BaseModel):
    message: str

class TokenResponse(BaseModel):
    token: str
    message: str

class SecretResponse(BaseModel):
    secret: str

# ===========================
# Dependencies
# ===========================
def get_authorization_username(authorization: Optional[str] = Header(default=None)) -> str:
    if not authorization or not isinstance(authorization, str):
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    token = parts[1]
    payload = decode_access_token(token)
    sub = payload.get("sub")
    if not sub or not isinstance(sub, str):
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    return sub

def ensure_user_matches_request(token_username: str, request_username: str):
    # Use constant-time compare to avoid timing leaks
    if not hmac.compare_digest(token_username, request_username):
        raise HTTPException(status_code=401, detail="Invalid authentication token")

# ===========================
# Exception Handlers
# ===========================
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Conform response format for error messages
    if exc.status_code in (400, 401, 403, 404):
        # Map details to schema requirement
        detail = exc.detail if isinstance(exc.detail, str) else "Request failed"
        return JSONResponse(status_code=exc.status_code, content={"message": detail})
    # For other errors, avoid leaking details
    return JSONResponse(status_code=500, content={"message": "Internal server error"})

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Avoid leaking internal details, fulfill CWE-703
    return JSONResponse(status_code=500, content={"message": "Internal server error"})

# ===========================
# Startup
# ===========================
@app.on_event("startup")
def on_startup():
    # Initialize database
    init_db()

# ===========================
# Routes
# ===========================
@app.post("/register", response_model=MessageResponse, status_code=201, tags=["Authentication"])
def register_user(payload: RegisterRequest = Body(...)):
    try:
        success = create_user(payload.email.lower(), payload.username, payload.password)
    except Exception:
        # Do not leak the exact reason
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    if not success:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    return {"message": "Registration successful"}

@app.post("/login", response_model=TokenResponse, tags=["Authentication"])
def login_user(payload: LoginRequest = Body(...)):
    user = get_user_by_email(payload.email.lower())
    # Avoid user enumeration by using the same error message
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token(user["username"])
    return {"token": token, "message": "Login successful"}

@app.post("/set_secret", response_model=MessageResponse)
def set_secret_endpoint(
    payload: SetSecretRequest = Body(...),
    token_username: str = Depends(get_authorization_username),
):
    ensure_user_matches_request(token_username, payload.username)
    # If user doesn't exist, treat as unauthorized to avoid leaking user existence
    if not get_user_by_username(payload.username):
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    # Store the secret as provided. In a real world scenario, consider encrypting at rest.
    try:
        ok = set_secret_for_user(payload.username, payload.secret)
    except Exception:
        # Catch unexpected DB errors
        raise HTTPException(status_code=500, detail="Internal server error")
    if not ok:
        # If couldn't set because user missing, treat as unauthorized
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", response_model=SecretResponse)
def get_secret_endpoint(
    username: str = Query(..., min_length=3, max_length=30),
    token_username: str = Depends(get_authorization_username),
):
    if not USERNAME_REGEX.fullmatch(username):
        # Generic unauthorized to not leak info
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    ensure_user_matches_request(token_username, username)
    # If user doesn't exist, treat as unauthorized per schema (no 404 defined)
    if not get_user_by_username(username):
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    try:
        secret = get_secret_for_user(username)
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")
    if secret is None:
        # User exists, but None implies unexpected state; return empty
        secret = ""
    return {"secret": secret}

# ===========================
# Main
# ===========================
if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000 as requested
    uvicorn.run(app, host="0.0.0.0", port=5000)