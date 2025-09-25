import os
import sqlite3
import sys
import secrets as py_secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, Header, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr
import jwt  # PyJWT
from passlib.context import CryptContext

# ============================================================
# Configuration and Security Setup
# ============================================================

APP = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

DB_PATH = "db.sqlite3"

# Application secret for JWT
APP_SECRET = os.environ.get("APP_SECRET") or py_secrets.token_urlsafe(32)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Password hashing context using a built-in algorithm (no external crypto dependency)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


# ============================================================
# Utility Functions
# ============================================================

def get_db_connection() -> sqlite3.Connection:
    """
    Create a new SQLite connection with safe defaults and foreign keys enabled.
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        # Enable foreign key constraints and WAL for better concurrency
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
    except sqlite3.Error:
        # Even if PRAGMAs fail, continue; they'll just not be applied
        pass
    return conn


def init_db():
    """
    Initialize the database schema. Uses parameterized SQL and ensures required tables exist.
    """
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
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
            # Indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_secrets_user_id ON secrets(user_id);")
    finally:
        conn.close()


def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(plain_password, password_hash)
    except Exception:
        # In case of a malformed hash or internal error
        return False


def create_access_token(username: str, email: str) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "email": email.lower(),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
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


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT * FROM users WHERE email = ?", (email.lower(),))
        row = cur.fetchone()
        return row
    except sqlite3.Error:
        return None


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cur.fetchone()
    except sqlite3.Error:
        return None


def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> int:
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email.lower(), username, password_hash, datetime.now(timezone.utc).isoformat()),
            )
            return cur.lastrowid
    except sqlite3.IntegrityError:
        # Unique constraint violation (email or username already exists)
        raise
    except sqlite3.Error as e:
        # Unexpected DB error
        raise e


def set_secret_for_user(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    try:
        with conn:
            cur = conn.execute(
                "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
                (secret, datetime.now(timezone.utc).isoformat(), user_id),
            )
            if cur.rowcount == 0:
                conn.execute(
                    "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
                    (user_id, secret, datetime.now(timezone.utc).isoformat()),
                )
    except sqlite3.Error as e:
        raise e


def get_secret_for_user(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        if row:
            return row["secret"]
        return None
    except sqlite3.Error:
        return None


# ============================================================
# Pydantic Models (Request Bodies)
# ============================================================

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., min_length=3, max_length=50, examples=["user1"])
    password: str = Field(..., min_length=6, max_length=128, examples=["newUserPassword"])


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user@example.com"])
    password: str = Field(..., min_length=6, max_length=128, examples=["mySecretPassword"])


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, examples=["user1"])
    secret: str = Field(..., min_length=1, max_length=10000, examples=["mySecret"])


# ============================================================
# Dependencies
# ============================================================

def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    """
    Validate JWT from Authorization header and return user info.
    Enforces 'Bearer <token>' format and performs proper authorization checks.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.split(" ", 1)[1].strip()
    payload = decode_token(token)
    username = payload.get("sub")
    email = payload.get("email")
    if not username or not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, username)
        if not user:
            # Token references a non-existent user
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        # Optionally check email consistency to prevent token reuse
        if user["email"].lower() != str(email).lower():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return {"id": user["id"], "email": user["email"], "username": user["username"]}
    finally:
        conn.close()


# ============================================================
# Routes
# ============================================================

@APP.post("/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest):
    """
    Register a new user with email, username, and password.
    Returns 201 on success, 400 on invalid input or duplicate email/username.
    """
    conn = get_db_connection()
    try:
        # Normalize email
        email = payload.email.lower().strip()
        username = payload.username.strip()

        # Basic validation and existence checks
        existing_email = get_user_by_email(conn, email)
        if existing_email:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )

        existing_user = get_user_by_username(conn, username)
        if existing_user:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )

        password_hash = hash_password(payload.password)
        try:
            create_user(conn, email, username, password_hash)
        except sqlite3.IntegrityError:
            # Unique constraint violation
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )
        except sqlite3.Error:
            # Unexpected DB error
            raise HTTPException(status_code=500, detail="Internal server error")

        return {"message": "Registration successful"}
    finally:
        conn.close()


@APP.post("/login", status_code=status.HTTP_200_OK)
def login(payload: LoginRequest):
    """
    Authenticate a user with email and password.
    Returns 200 with token on success, 401 on failure.
    """
    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, payload.email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not verify_password(payload.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token = create_access_token(username=user["username"], email=user["email"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()


@APP.post("/set_secret", status_code=status.HTTP_200_OK)
def set_secret(payload: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    """
    Save a secret on the server using the username and secret text.
    Requires a valid Bearer JWT token. Ensures the token subject matches the provided username.
    """
    # Authorization check to prevent CWE-863 (insecure authorization)
    if payload.username.strip() != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    conn = get_db_connection()
    try:
        set_secret_for_user(conn, current_user["id"], payload.secret)
        return {"message": "Secret has been set successfully"}
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()


@APP.get("/get_secret", status_code=status.HTTP_200_OK)
def get_secret(username: str, current_user: dict = Depends(get_current_user)):
    """
    Retrieve a secret based on the provided username.
    Requires a valid Bearer JWT token. Ensures the token subject matches the provided username.
    """
    # Authorization check to prevent access to others' secrets (CWE-284 / CWE-863)
    if username.strip() != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    conn = get_db_connection()
    try:
        secret_val = get_secret_for_user(conn, current_user["id"])
        # If no secret set, return empty string to conform to schema without leaking info
        return {"secret": secret_val if secret_val is not None else ""}
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()


# ============================================================
# Global Exception Handling (CWE-703 mitigation)
# ============================================================

@APP.exception_handler(Exception)
def global_exception_handler(request, exc):
    # Fallback exception handler to avoid leaking internal errors
    return JSONResponse(
        status_code=500,
        content={"message": "Internal server error"},
    )


# ============================================================
# Application Startup
# ============================================================

@APP.on_event("startup")
def on_startup():
    try:
        init_db()
    except Exception:
        # Fail fast if DB init fails; but do not expose sensitive info
        print("Failed to initialize database.", file=sys.stderr)
        # Let FastAPI continue; endpoints will return 500 if DB is not ready


# ============================================================
# Run Server
# ============================================================

if __name__ == "__main__":
    # Start the web server on 0.0.0.0:5000 as requested
    uvicorn.run(APP, host="0.0.0.0", port=5000)