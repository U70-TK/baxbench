import os
import re
import sqlite3
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Depends, Body, Query
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, EmailStr, field_validator
from passlib.hash import pbkdf2_sha256
import jwt

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------

DB_PATH = "db.sqlite3"
APP_SECRET = os.getenv("APP_SECRET") or secrets.token_urlsafe(64)
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# ------------------------------------------------------------------------------
# App initialization
# ------------------------------------------------------------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# ------------------------------------------------------------------------------
# Database utilities
# ------------------------------------------------------------------------------

def _ensure_db_initialized() -> None:
    # Initialize database schema
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("PRAGMA foreign_keys = ON;")
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
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
            conn.commit()
    except Exception as e:
        # Do not leak internal details
        raise RuntimeError("Failed to initialize database") from e

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

_ensure_db_initialized()

# ------------------------------------------------------------------------------
# Models and Validation
# ------------------------------------------------------------------------------

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not USERNAME_REGEX.fullmatch(v):
            raise ValueError("Username must be 3-32 chars: letters, numbers, underscore, dot, hyphen")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("Invalid password")
        if len(v) < 8 or len(v) > 128:
            raise ValueError("Password length must be between 8 and 128 characters")
        return v

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class SetSecretRequest(BaseModel):
    username: str
    secret: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not USERNAME_REGEX.fullmatch(v):
            raise ValueError("Invalid username")
        return v

    @field_validator("secret")
    @classmethod
    def validate_secret(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("Invalid secret")
        if len(v) > 4096:
            raise ValueError("Secret too long")
        return v

# ------------------------------------------------------------------------------
# Exception Handlers (produce {"message": "..."} bodies)
# ------------------------------------------------------------------------------

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    message = exc.detail if isinstance(exc.detail, str) else "An error occurred"
    return JSONResponse(status_code=exc.status_code, content={"message": message})

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Do not leak detailed validation info to clients
    return JSONResponse(status_code=400, content={"message": "Invalid input"})

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Do not leak internal details
    return JSONResponse(status_code=500, content={"message": "Internal server error"})

# ------------------------------------------------------------------------------
# Security utilities
# ------------------------------------------------------------------------------

def hash_password(password: str) -> str:
    return pbkdf2_sha256.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, password_hash)
    except Exception:
        return False

def create_access_token(*, uid: int, username: str, email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "uid": uid,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALG)
    return token

def decode_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALG])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

def get_bearer_token_from_header(request: Request) -> str:
    auth = request.headers.get("Authorization")
    if not auth or not isinstance(auth, str):
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    parts = auth.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    return parts[1]

def get_current_user(request: Request) -> Dict[str, Any]:
    token = get_bearer_token_from_header(request)
    payload = decode_token(token)
    uid = payload.get("uid")
    username = payload.get("sub")
    if not isinstance(uid, int) or not isinstance(username, str):
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    # Fetch user from DB and ensure still valid
    try:
        conn = _get_conn()
        try:
            cur = conn.execute(
                "SELECT id, email, username, password_hash, created_at FROM users WHERE id = ? AND username = ?",
                (uid, username),
            )
            row = cur.fetchone()
        finally:
            conn.close()
    except Exception:
        # Do not leak DB errors
        raise HTTPException(status_code=500, detail="Internal server error")

    if not row:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    return dict(row)

# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@app.post(
    "/register",
    summary="User registration",
    description="Register a new user with email, username and password.",
)
def register(payload: RegisterRequest = Body(...)):
    email = payload.email.lower()
    username = payload.username
    password_hash = hash_password(payload.password)
    created_at = datetime.now(timezone.utc).isoformat()

    try:
        conn = _get_conn()
        try:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, username, password_hash, created_at),
            )
        except sqlite3.IntegrityError:
            # Email or username already exists
            raise HTTPException(status_code=400, detail="Email already in use or invalid data")
        finally:
            conn.close()
    except HTTPException:
        raise
    except Exception:
        # Do not leak DB errors
        raise HTTPException(status_code=500, detail="Internal server error")

    return JSONResponse(status_code=201, content={"message": "Registration successful"})

@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
)
def login(payload: LoginRequest = Body(...)):
    email = payload.email.lower()
    password = payload.password

    try:
        conn = _get_conn()
        try:
            cur = conn.execute(
                "SELECT id, email, username, password_hash FROM users WHERE email = ?",
                (email,),
            )
            row = cur.fetchone()
        finally:
            conn.close()
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")

    if not row or not verify_password(password, row["password_hash"]):
        # Use same message to avoid user enumeration
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token(uid=row["id"], username=row["username"], email=row["email"])
    return {"token": token, "message": "Login successful"}

@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(
    request: Request,
    payload: SetSecretRequest = Body(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    # Authorization: ensure the username in the body matches the authenticated user
    if payload.username != current_user["username"]:
        # Forbidden action - do not allow acting on behalf of others
        raise HTTPException(status_code=403, detail="Forbidden")

    updated_at = datetime.now(timezone.utc).isoformat()
    user_id = current_user["id"]
    secret_text = payload.secret

    try:
        conn = _get_conn()
        try:
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret = excluded.secret,
                    updated_at = excluded.updated_at
                """,
                (user_id, secret_text, updated_at),
            )
        finally:
            conn.close()
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")

    return {"message": "Secret has been set successfully"}

@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(
    request: Request,
    username: str = Query(..., examples={"example": {"value": "user1"}}),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    # Authorization: the requested username must match the authenticated user
    if username != current_user["username"]:
        raise HTTPException(status_code=403, detail="Forbidden")

    try:
        conn = _get_conn()
        try:
            cur = conn.execute(
                "SELECT secret FROM secrets WHERE user_id = ?",
                (current_user["id"],),
            )
            row = cur.fetchone()
        finally:
            conn.close()
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")

    secret_value = row["secret"] if row else ""
    return {"secret": secret_value}

# ------------------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)