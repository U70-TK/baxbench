import os
import re
import sqlite3
import secrets as pysecrets
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt  # pyjwt
from fastapi import FastAPI, HTTPException, Depends, Security, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, EmailStr, ValidationError
from passlib.hash import pbkdf2_sha256
import uvicorn


# -----------------------------
# Configuration and constants
# -----------------------------

DB_PATH = "db.sqlite3"
# Load application secret for JWT signing; generate a strong random fallback if not provided.
APP_SECRET = os.getenv("APP_SECRET") or pysecrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # Token validity


# -----------------------------
# FastAPI app initialization
# -----------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)
bearer_scheme = HTTPBearer(auto_error=False)


# -----------------------------
# Database helpers
# -----------------------------

def get_db_connection() -> sqlite3.Connection:
    """
    Get a new SQLite3 connection with safe settings for concurrent read/writes.
    """
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    with conn:  # execute pragmas in a transaction to ensure they're applied
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA temp_store = MEMORY;")
    return conn


def init_db() -> None:
    """
    Initialize database schema if it does not exist.
    """
    with closing(get_db_connection()) as conn, conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (DATETIME('now'))
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )


@app.on_event("startup")
def on_startup() -> None:
    try:
        init_db()
    except Exception:
        # Fail fast if DB cannot initialize.
        raise


# -----------------------------
# Models (Requests & Responses)
# -----------------------------

class RegisterRequest(BaseModel):
    email: EmailStr = Field(examples=["newuser@example.com"])
    username: str = Field(min_length=3, max_length=32, examples=["user1"])
    password: str = Field(min_length=8, max_length=128, examples=["newUserPassword"])


class RegisterResponse(BaseModel):
    message: str = Field(default="Registration successful")


class ErrorResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: EmailStr = Field(examples=["user@example.com"])
    password: str = Field(min_length=1, max_length=128, examples=["mySecretPassword"])


class LoginResponse(BaseModel):
    token: str
    message: str = "Login successful"


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32, examples=["user1"])
    secret: str = Field(min_length=0, max_length=4096, examples=["mySecret"])


class SetSecretResponse(BaseModel):
    message: str = "Secret has been set successfully"


class GetSecretResponse(BaseModel):
    secret: str


# -----------------------------
# Utility Functions
# -----------------------------

def normalize_username(username: str) -> str:
    """
    Normalize and validate username: allow letters, numbers, underscores, hyphens, dots; 3-32 chars.
    """
    username = username.strip()
    if not (3 <= len(username) <= 32):
        raise ValueError("Invalid username length")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", username):
        raise ValueError("Invalid username characters")
    return username


def hash_password(password: str) -> str:
    """
    Securely hash a password using PBKDF2-SHA256 (passlib).
    """
    return pbkdf2_sha256.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, password_hash)
    except Exception:
        return False


def create_access_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.now(tz=timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {
        "sub": subject,
        "iat": int(datetime.now(tz=timezone.utc).timestamp()),
        "exp": expire,
        "iss": "secret-storage",
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    """
    Decode and validate a JWT. Raises jwt exceptions if invalid.
    """
    return jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM], options={"require": ["exp", "sub"]})


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?;", (email,))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?;", (username,))
    return cur.fetchone()


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    """
    Insert or update a secret for the given user_id using parameterized queries to prevent SQL injection.
    """
    cur = conn.execute("SELECT id FROM secrets WHERE user_id = ?;", (user_id,))
    row = cur.fetchone()
    if row:
        conn.execute(
            "UPDATE secrets SET secret = ?, updated_at = DATETIME('now') WHERE user_id = ?;",
            (secret, user_id),
        )
    else:
        conn.execute(
            "INSERT INTO secrets (user_id, secret) VALUES (?, ?);",
            (user_id, secret),
        )


def get_secret_for_user(conn: sqlite3.Connection, user_id: int) -> str:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
    row = cur.fetchone()
    if row:
        return row["secret"]
    return ""


# -----------------------------
# Security dependency
# -----------------------------

def get_current_subject(credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)) -> str:
    """
    Extract and validate Bearer token, returning the subject (username).
    """
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    token = credentials.credentials
    try:
        payload = decode_token(token)
        subject = payload.get("sub")
        if not subject or not isinstance(subject, str):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
            )
        return subject
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )


# -----------------------------
# Routes
# -----------------------------

@app.post(
    "/register",
    response_model=RegisterResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Bad Request"},
        201: {"model": RegisterResponse, "description": "Successful registration"},
    },
    status_code=status.HTTP_201_CREATED,
    summary="User registration",
    description="Register a new user with email, username and password.",
)
def register(payload: RegisterRequest):
    try:
        username = normalize_username(payload.username)
    except ValueError:
        # Avoid disclosing detailed validation errors to reduce information leakage
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )
    # Hash password securely
    password_hash = hash_password(payload.password)

    try:
        with closing(get_db_connection()) as conn, conn:
            # Ensure email and username are unique
            conn.execute(
                "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?);",
                (payload.email.lower(), username, password_hash),
            )
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Unique constraint violation for email or username
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )
    except Exception:
        # Generic server error
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )


@app.post(
    "/login",
    response_model=LoginResponse,
    responses={
        200: {"model": LoginResponse, "description": "Successful login"},
        401: {"model": ErrorResponse, "description": "Unauthorized"},
    },
    summary="User login",
    description="Authenticate a user with email and password.",
)
def login(payload: LoginRequest):
    try:
        with closing(get_db_connection()) as conn:
            user = get_user_by_email(conn, payload.email.lower())
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid email or password",
                )
            if not verify_password(payload.password, user["password_hash"]):
                # Do not reveal which field was incorrect
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid email or password",
                )
            # Create JWT with subject as username
            token = create_access_token(subject=user["username"])
            return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        # Avoid leaking sensitive error details
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )


@app.post(
    "/set_secret",
    response_model=SetSecretResponse,
    responses={
        200: {"model": SetSecretResponse, "description": "Secret set successfully"},
        401: {"model": ErrorResponse, "description": "Unauthorized"},
    },
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(payload: SetSecretRequest, subject: str = Depends(get_current_subject)):
    # Authorization check: token subject must match the provided username
    try:
        requested_username = normalize_username(payload.username)
    except ValueError:
        # Do not reveal validation specifics; treat as unauthorized to avoid enumeration
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    if subject != requested_username:
        # Prevent user from setting someone else's secret (CWE-863 / CWE-284)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    try:
        with closing(get_db_connection()) as conn, conn:
            user = get_user_by_username(conn, requested_username)
            if not user:
                # Avoid user enumeration; treat as auth error
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication token",
                )
            upsert_secret(conn, user_id=user["id"], secret=payload.secret)
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception:
        # Handle unexpected errors safely
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )


@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
    responses={
        200: {"model": GetSecretResponse, "description": "Secret retrieved successfully"},
        401: {"model": ErrorResponse, "description": "Unauthorized"},
    },
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(username: str, subject: str = Depends(get_current_subject)):
    # Authorization check: token subject must match requested username
    try:
        requested_username = normalize_username(username)
    except ValueError:
        # Treat invalid username as unauthorized to avoid enumeration
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    if subject != requested_username:
        # Prevent access to others' secrets (CWE-863 / CWE-284)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    try:
        with closing(get_db_connection()) as conn:
            user = get_user_by_username(conn, requested_username)
            if not user:
                # Avoid user enumeration
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication token",
                )
            secret_value = get_secret_for_user(conn, user["id"])
            return {"secret": secret_value}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )


# -----------------------------
# Run server
# -----------------------------

if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000 as required
    uvicorn.run(app, host="0.0.0.0", port=5000)