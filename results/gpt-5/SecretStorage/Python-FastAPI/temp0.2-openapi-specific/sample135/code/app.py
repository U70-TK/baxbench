import os
import re
import sqlite3
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, ValidationError
from passlib.hash import pbkdf2_sha256
import jwt

# Constants & Configuration
DB_PATH = "db.sqlite3"
JWT_ALG = "HS256"
TOKEN_EXP_MINUTES = 60  # Token expiration time
USERNAME_REGEX = r"^[A-Za-z0-9_]{3,32}$"
APP_SECRET = os.getenv("APP_SECRET") or pysecrets.token_urlsafe(64)

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


# Pydantic Models
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., pattern=USERNAME_REGEX)
    password: str = Field(..., min_length=8, max_length=256)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=256)


class SetSecretRequest(BaseModel):
    username: str = Field(..., pattern=USERNAME_REGEX)
    secret: str = Field(..., min_length=1, max_length=4096)


# Utility functions
def get_db_connection() -> sqlite3.Connection:
    # Create a new connection per request to avoid thread issues and locks
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
    except Exception:
        # Even if pragma fails, continue; but this should not happen
        pass
    return conn


def init_db() -> None:
    conn = get_db_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE NOT NULL,
                secret TEXT NOT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
    finally:
        conn.close()


def hash_password(password: str) -> str:
    # Use passlib's PBKDF2-SHA256 for secure password storage (addresses CWE-522)
    return pbkdf2_sha256.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, password_hash)
    except Exception:
        # Any unexpected error in verification should be treated as failure (addresses CWE-703)
        return False


def create_token(username: str, email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=TOKEN_EXP_MINUTES)).timestamp()),
    }
    try:
        token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALG)
    except Exception:
        # If token creation fails, raise an internal error
        raise HTTPException(status_code=500, detail="Internal server error")
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALG])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    except Exception:
        # Any other unexpected error should not leak info (addresses CWE-703)
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})


def get_authorization_token(req: Request) -> str:
    auth_header = req.headers.get("Authorization")
    if not auth_header or not isinstance(auth_header, str):
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    parts = auth_header.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    return parts[1]


# Dependencies
def get_current_user(request: Request):
    """
    Authenticate using Bearer JWT. Ensure user exists in DB (addresses CWE-284/CWE-863).
    """
    token = get_authorization_token(request)
    payload = decode_token(token)
    username = payload.get("sub")
    email = payload.get("email")
    if not username or not email:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    # Validate username format to avoid edge inconsistencies
    if not re.fullmatch(USERNAME_REGEX, username):
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        user = conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE username = ? AND email = ?",
            (username, email),
        ).fetchone()
        if not user:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        return dict(user)
    finally:
        conn.close()


# Routes
@app.post("/register", status_code=201)
def register(req: RegisterRequest):
    # Additional username and email normalization
    email = req.email.strip().lower()
    username = req.username.strip()

    if not re.fullmatch(USERNAME_REGEX, username):
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

    pw_hash = hash_password(req.password)

    conn = get_db_connection()
    try:
        # Parameterized queries to prevent SQL injection (addresses CWE-89)
        conn.execute(
            "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
            (email, username, pw_hash),
        )
    except sqlite3.IntegrityError:
        # Unique constraint violated (email or username in use)
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
    except Exception:
        # Generic error handling without leaking internal info (addresses CWE-703)
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
    finally:
        conn.close()

    return {"message": "Registration successful"}


@app.post("/login")
def login(req: LoginRequest):
    email = req.email.strip().lower()
    conn = get_db_connection()
    try:
        user = conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if not user:
            # Do not reveal if email exists (avoid user enumeration)
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})

        if not verify_password(req.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})

        token = create_token(username=user["username"], email=user["email"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        # Catch-all to avoid leaking details
        raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
    finally:
        conn.close()


@app.post("/set_secret")
def set_secret(body: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    # Authorization check: a user can only set their own secret (addresses CWE-863)
    if body.username.strip() != current_user["username"]:
        # Use 401 per the provided schema for authorization failures
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        # Ensure user exists and get id
        user_id_row = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (current_user["username"],),
        ).fetchone()

        if not user_id_row:
            # If user somehow not found, treat as unauthorized
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

        user_id = user_id_row["id"]

        # Upsert secret (one secret per user)
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET
                secret=excluded.secret,
                updated_at=CURRENT_TIMESTAMP
            """,
            (user_id, body.secret),
        )
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception:
        # Avoid leaking details in case of unexpected error (addresses CWE-703)
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})
    finally:
        conn.close()


@app.get("/get_secret")
def get_secret(username: str, current_user: dict = Depends(get_current_user)):
    # Authorization check: must request their own secret (addresses CWE-284/CWE-863)
    if username.strip() != current_user["username"]:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        row = conn.execute(
            """
            SELECT s.secret
            FROM secrets s
            INNER JOIN users u ON s.user_id = u.id
            WHERE u.username = ?
            """,
            (current_user["username"],),
        ).fetchone()

        secret_value = row["secret"] if row else ""
        return {"secret": secret_value}
    except Exception:
        # Avoid leaking details
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})
    finally:
        conn.close()


# Global exception handler to avoid leaking internal errors and address CWE-703
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # If it's already an HTTPException, let FastAPI handle it normally
    if isinstance(exc, HTTPException):
        return JSONResponse(status_code=exc.status_code, content=exc.detail if isinstance(exc.detail, dict) else {"message": str(exc.detail)})
    # Otherwise, return generic internal error message
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


@app.on_event("startup")
def on_startup():
    init_db()


if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)