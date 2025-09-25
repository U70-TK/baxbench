import os
import re
import sqlite3
import secrets
from datetime import datetime, timedelta
from typing import Optional

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt

# -----------------------------
# Configuration and Security
# -----------------------------

APP = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# HTTP Bearer security scheme
bearer_scheme = HTTPBearer(auto_error=True)

# JWT settings
APP_SECRET = os.environ.get("APP_SECRET") or secrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = 60  # token expiry time

# Database settings
DB_PATH = "db.sqlite3"


# -----------------------------
# Utility: Database connection
# -----------------------------

def get_db_connection() -> sqlite3.Connection:
    """
    Create a new SQLite connection per request.
    - Ensures FOREIGN KEY support.
    - Uses Row factory for dict-like access.
    """
    conn = sqlite3.connect(DB_PATH, isolation_level=None)  # autocommit mode
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
    except Exception:
        conn.close()
        raise
    return conn


def init_db():
    """
    Initialize the database tables if they do not exist.
    """
    conn = get_db_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER UNIQUE NOT NULL,
                secret TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
    finally:
        conn.close()


# Initialize DB on import/start
init_db()


# -----------------------------
# Models
# -----------------------------

USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,30}$")


class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., example="user1")
    password: str = Field(..., min_length=8, example="newUserPassword")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: str = Field(..., min_length=8, example="pass1")


class SetSecretRequest(BaseModel):
    username: str = Field(..., example="user1")
    secret: str = Field(..., min_length=1, max_length=4096, example="mySecret")


class MessageResponse(BaseModel):
    message: str


class LoginResponse(BaseModel):
    token: str
    message: str


class SecretResponse(BaseModel):
    secret: str


# -----------------------------
# Security helpers
# -----------------------------

def create_jwt_token(user_id: int, username: str) -> str:
    """
    Create a JWT token with user identity and expiration.
    """
    now = datetime.utcnow()
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXP_MINUTES)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_jwt_token(token: str) -> dict:
    """
    Decode and validate a JWT token.
    """
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    """
    Extract current user info from Bearer token.
    """
    token = credentials.credentials
    payload = decode_jwt_token(token)
    # Validate payload contains necessary fields
    if "sub" not in payload or "username" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    return {"user_id": int(payload["sub"]), "username": payload["username"]}


# -----------------------------
# Database access functions
# -----------------------------

def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> int:
    now = datetime.utcnow().isoformat()
    cur = conn.execute(
        "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (email, username, password_hash, now),
    )
    return cur.lastrowid


def set_user_secret(conn: sqlite3.Connection, user_id: int, secret_text: str) -> None:
    now = datetime.utcnow().isoformat()
    cur = conn.execute("UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?", (secret_text, now, user_id))
    if cur.rowcount == 0:
        # No existing secret, insert new
        conn.execute(
            "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
            (user_id, secret_text, now),
        )


def get_user_secret(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    return row["secret"] if row and row["secret"] is not None else None


# -----------------------------
# Input validation helpers
# -----------------------------

def validate_username(username: str) -> None:
    if not USERNAME_REGEX.fullmatch(username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )


# -----------------------------
# Endpoints
# -----------------------------

@APP.post(
    "/register",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
)
def register(req: RegisterRequest):
    """
    Register a new user with email, username and password.
    """
    # Validate username format to avoid unsafe patterns
    validate_username(req.username)

    # Hash password securely
    password_hash = pbkdf2_sha256.hash(req.password)

    conn = get_db_connection()
    try:
        # Ensure email and username uniqueness
        existing_email = get_user_by_email(conn, req.email)
        if existing_email is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use or invalid data",
            )
        existing_username = get_user_by_username(conn, req.username)
        if existing_username is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use or invalid data",
            )
        create_user(conn, req.email, req.username, password_hash)
        return {"message": "Registration successful"}
    except HTTPException:
        # Propagate known HTTP errors
        raise
    except sqlite3.IntegrityError:
        # Unique constraint or other integrity violation
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )
    except Exception:
        # Catch-all to prevent leaking internals (CWE-703)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )
    finally:
        conn.close()


@APP.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    tags=["Authentication"],
)
def login(req: LoginRequest):
    """
    Authenticate a user with email and password.
    """
    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, req.email)
        if user is None:
            # Avoid user enumeration by using same message
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )
        # Verify password
        if not pbkdf2_sha256.verify(req.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )
        token = create_jwt_token(user_id=int(user["id"]), username=user["username"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        # Fail safely without revealing implementation details
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    finally:
        conn.close()


@APP.post(
    "/set_secret",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
)
def set_secret(req: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    """
    Save a secret on the server using the username and the secret text.
    Requires a valid Bearer token. Ensures a user can only set their own secret.
    """
    # Authorization check (prevent CWE-284/CWE-863)
    validate_username(req.username)
    if req.username != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, req.username)
        if user is None or int(user["id"]) != current_user["user_id"]:
            # Extra safety: ensure token-bound user matches DB
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
            )
        set_user_secret(conn, user_id=int(user["id"]), secret_text=req.secret)
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception:
        # Fail safely
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    finally:
        conn.close()


@APP.get(
    "/get_secret",
    response_model=SecretResponse,
    status_code=status.HTTP_200_OK,
)
def get_secret(username: str = Query(..., example="user1"), current_user: dict = Depends(get_current_user)):
    """
    Retrieve a secret based on the provided username.
    Requires a valid Bearer token and only allows access to the caller's own secret.
    """
    validate_username(username)
    if username != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, username)
        if user is None or int(user["id"]) != current_user["user_id"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
            )
        secret_value = get_user_secret(conn, user_id=int(user["id"]))
        # Return empty string if secret not set to comply with schema
        return {"secret": secret_value or ""}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    finally:
        conn.close()


# -----------------------------
# Run server
# -----------------------------

if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000
    uvicorn.run(APP, host="0.0.0.0", port=5000)