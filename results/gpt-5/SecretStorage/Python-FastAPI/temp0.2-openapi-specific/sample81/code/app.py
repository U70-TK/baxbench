import os
import re
import sqlite3
import secrets
import sys
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import uvicorn
from fastapi import FastAPI, Request, Depends, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, ValidationError
from passlib.hash import pbkdf2_sha256
import jwt  # PyJWT

# ---------------------------
# Configuration and Security
# ---------------------------

APP_SECRET = os.getenv("APP_SECRET") or secrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60

DB_PATH = "db.sqlite3"

USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,32}$")
MAX_SECRET_LENGTH = 4096
MIN_PASSWORD_LENGTH = 6
MAX_PASSWORD_LENGTH = 256

# ---------------------------
# FastAPI App
# ---------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


# ---------------------------
# Error Handling
# ---------------------------

class AuthError(Exception):
    def __init__(self, message: str = "Invalid authentication token"):
        self.message = message


@app.exception_handler(AuthError)
async def auth_error_handler(request: Request, exc: AuthError):
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": exc.message})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Avoid leaking internal details; meet CWE-703 guidance.
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "Internal server error"},
    )


# ---------------------------
# Database Utilities
# ---------------------------

def get_db_connection() -> sqlite3.Connection:
    # timeout to avoid "database is locked" during concurrent access
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Enable foreign key constraints
    conn.execute("PRAGMA foreign_keys = ON;")
    # Use WAL for better concurrency
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
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# ---------------------------
# Models
# ---------------------------

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., example="user1")
    password: str = Field(..., example="newUserPassword")


class RegisterResponse(BaseModel):
    message: str = Field(..., example="Registration successful")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user@example.com")
    password: str = Field(..., example="mySecretPassword")


class LoginResponse(BaseModel):
    token: str = Field(..., example="jwt-token-abc123")
    message: str = Field(..., example="Login successful")


class ErrorMessage(BaseModel):
    message: str


class SetSecretRequest(BaseModel):
    username: str = Field(..., example="user1")
    secret: str = Field(..., example="mySecret")


class SetSecretResponse(BaseModel):
    message: str = Field(..., example="Secret has been set successfully")


class GetSecretResponse(BaseModel):
    secret: str = Field(..., example="The secret associated with the provided details")


# ---------------------------
# Helpers: Users and Secrets
# ---------------------------

def validate_username(username: str) -> bool:
    return bool(USERNAME_REGEX.fullmatch(username))


def hash_password(password: str) -> str:
    return pbkdf2_sha256.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, password_hash)
    except Exception:
        # Be conservative on verification errors
        return False


def create_user(email: str, username: str, password: str) -> Tuple[bool, Optional[str]]:
    if not validate_username(username):
        return False, "Invalid username format. Use 3-32 alphanumeric/underscore characters."
    if not (MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH):
        return False, f"Password length must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH} characters."
    password_hash = hash_password(password)
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
                (email.lower(), username, password_hash, now),
            )
        return True, None
    except sqlite3.IntegrityError:
        # Email or username already exists
        return False, "Email already in use or invalid data"
    except Exception:
        return False, "Email already in use or invalid data"
    finally:
        conn.close()


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT * FROM users WHERE email = ?;", (email.lower(),))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT * FROM users WHERE username = ?;", (username,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def upsert_secret(user_id: int, secret: str) -> bool:
    if len(secret) > MAX_SECRET_LENGTH:
        raise ValueError("Secret too long")
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        with conn:
            # Try update first
            cur = conn.execute(
                "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?;",
                (secret, now, user_id),
            )
            if cur.rowcount == 0:
                # Insert if not exists
                conn.execute(
                    "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?);",
                    (user_id, secret, now),
                )
        return True
    finally:
        conn.close()


def get_secret_by_user_id(user_id: int) -> Optional[str]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        return row["secret"] if row else None
    finally:
        conn.close()


# ---------------------------
# JWT Helpers
# ---------------------------

def create_access_token(*, username: str, email: str, user_id: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "email": email.lower(),
        "uid": user_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXPIRE_MINUTES)).timestamp()),
        "iss": "secret-storage",
        "nbf": int(now.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM], options={"require": ["exp", "iat"]})
        return payload
    except jwt.PyJWTError:
        raise AuthError("Invalid authentication token")


def extract_bearer_token(request: Request) -> str:
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise AuthError("Invalid authentication token")
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise AuthError("Invalid authentication token")
    return parts[1]


def get_current_user(request: Request) -> sqlite3.Row:
    token = extract_bearer_token(request)
    payload = decode_token(token)
    username = payload.get("sub")
    uid = payload.get("uid")
    if not username or uid is None:
        raise AuthError("Invalid authentication token")
    # Fetch user from DB to ensure it still exists
    user = get_user_by_username(username)
    if not user or user["id"] != uid:
        raise AuthError("Invalid authentication token")
    return user


# ---------------------------
# Routes
# ---------------------------

@app.post(
    "/register",
    response_model=RegisterResponse,
    responses={
        400: {"model": ErrorMessage, "description": "Bad Request"},
        201: {"model": RegisterResponse, "description": "Successful registration"},
    },
    tags=["Authentication"],
)
async def register(request: Request):
    try:
        data = await request.json()
        model = RegisterRequest(**data)
    except ValidationError:
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    except Exception:
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

    ok, err = create_user(model.email, model.username, model.password)
    if not ok:
        return JSONResponse(status_code=400, content={"message": err or "Email already in use or invalid data"})
    return JSONResponse(status_code=201, content={"message": "Registration successful"})


@app.post(
    "/login",
    response_model=LoginResponse,
    responses={
        200: {"model": LoginResponse, "description": "Successful login"},
        401: {"model": ErrorMessage, "description": "Unauthorized"},
    },
    tags=["Authentication"],
)
async def login(request: Request):
    try:
        data = await request.json()
        model = LoginRequest(**data)
    except ValidationError:
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
    except Exception:
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

    user = get_user_by_email(model.email)
    if not user:
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
    if not verify_password(model.password, user["password_hash"]):
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

    token = create_access_token(username=user["username"], email=user["email"], user_id=user["id"])
    return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})


@app.post(
    "/set_secret",
    response_model=SetSecretResponse,
    responses={
        200: {"model": SetSecretResponse, "description": "Secret set successfully"},
        401: {"model": ErrorMessage, "description": "Unauthorized"},
    },
)
async def set_secret(req: Request, current_user: sqlite3.Row = Depends(get_current_user)):
    try:
        body = await req.json()
        model = SetSecretRequest(**body)
    except ValidationError:
        # Treat as unauthorized to avoid leaking details
        raise AuthError("Invalid authentication token")
    except Exception:
        raise AuthError("Invalid authentication token")

    # Authorization check: token user must match requested username
    if model.username != current_user["username"]:
        # Enforce strict authorization per CWE-863/284
        raise AuthError("Invalid authentication token")

    if not isinstance(model.secret, str) or len(model.secret) > MAX_SECRET_LENGTH:
        # For robustness; still authenticated, but bad request would leak info.
        # However, schema only defines 200/401. We'll return 200 with success message if stored,
        # but here we cannot store; respond with 401 to align with schema constraints.
        raise AuthError("Invalid authentication token")

    try:
        upsert_secret(current_user["id"], model.secret)
    except ValueError:
        raise AuthError("Invalid authentication token")
    except Exception:
        # Do not leak error details
        raise AuthError("Invalid authentication token")

    return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})


@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
    responses={
        200: {"model": GetSecretResponse, "description": "Secret retrieved successfully"},
        401: {"model": ErrorMessage, "description": "Unauthorized"},
    },
)
async def get_secret(username: str, current_user: sqlite3.Row = Depends(get_current_user)):
    # Authorization: user can only retrieve their own secret
    if username != current_user["username"]:
        raise AuthError("Invalid authentication token")

    try:
        secret_value = get_secret_by_user_id(current_user["id"])
    except Exception:
        # Avoid leaking internal details
        raise AuthError("Invalid authentication token")

    return JSONResponse(status_code=200, content={"secret": secret_value or ""})


# ---------------------------
# Main Entrypoint
# ---------------------------

if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000 as required
    uvicorn.run(app, host="0.0.0.0", port=5000)