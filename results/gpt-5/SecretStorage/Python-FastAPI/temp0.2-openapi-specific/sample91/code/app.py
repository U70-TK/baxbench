import os
import sqlite3
import secrets as secrets_mod
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, Request, status, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt

# Application configuration
APP_NAME = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

# Security configuration
APP_SECRET = os.environ.get("APP_SECRET") or secrets_mod.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 3600  # 1 hour

DB_PATH = "db.sqlite3"

app = FastAPI(title=APP_NAME, description=APP_DESCRIPTION, version=APP_VERSION)


# ---------------------------
# Database Utilities
# ---------------------------

def get_db_connection() -> sqlite3.Connection:
    """
    Create a new SQLite connection. This function returns a new connection per call
    to avoid sharing connections across threads, which can cause issues.
    """
    conn = sqlite3.connect(DB_PATH, isolation_level=None, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """
    Initialize the database schema if it doesn't exist.
    """
    conn = None
    try:
        conn = get_db_connection()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
    except sqlite3.Error:
        # Fail fast but don't expose internal details
        raise RuntimeError("Database initialization failed.")
    finally:
        if conn:
            conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# ---------------------------
# Models
# ---------------------------

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., description="User email address")
    username: str = Field(..., min_length=3, max_length=64, description="Unique username")
    password: str = Field(..., min_length=8, max_length=256, description="User password")


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=256)


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    secret: str = Field(..., min_length=1, max_length=8192)


# ---------------------------
# Helpers
# ---------------------------

def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_access_token(*, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    to_encode.update({"iat": int(now.timestamp())})
    expire = now + (expires_delta or timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS))
    to_encode.update({"exp": int(expire.timestamp())})
    # Add a JWT ID for replay mitigation and uniqueness
    to_encode.update({"jti": secrets_mod.token_hex(16), "type": "access"})
    token = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(plain_password, password_hash)
    except Exception:
        # In case of any unusual issues with the hash, fail securely.
        return False


def hash_password(password: str) -> str:
    # pbkdf2_sha256 is available in passlib without extra deps; parameters are sane defaults.
    return pbkdf2_sha256.hash(password)


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
        return cur.fetchone()
    except sqlite3.Error:
        return None


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT id, email, username FROM users WHERE username = ?", (username,))
        return cur.fetchone()
    except sqlite3.Error:
        return None


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret_text: str) -> bool:
    try:
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret=excluded.secret,
                updated_at=excluded.updated_at
            """,
            (user_id, secret_text, utcnow_iso()),
        )
        return True
    except sqlite3.Error:
        return False


def get_secret_for_user(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        if row:
            return row["secret"]
        return None
    except sqlite3.Error:
        return None


# ---------------------------
# Auth Dependency
# ---------------------------

async def get_current_user(request: Request) -> Dict[str, Any]:
    """
    Extract and validate the bearer token from the Authorization header.
    Returns a dict containing user_id, username, and email if valid.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        # Missing authentication header
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    try:
        prefix, token = auth_header.strip().split(" ", 1)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    if prefix.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    user_id = payload.get("uid")
    username = payload.get("sub")
    email = payload.get("email")
    if not user_id or not username or not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    # Verify user still exists
    conn = None
    try:
        conn = get_db_connection()
        user_row = get_user_by_username(conn, username)
        if not user_row or user_row["id"] != user_id or user_row["email"] != email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
    finally:
        if conn:
            conn.close()

    return {"user_id": user_id, "username": username, "email": email}


# ---------------------------
# Routes
# ---------------------------

@app.post("/register")
async def register(payload: RegisterRequest):
    """
    Register a new user with email, username, and password.
    """
    conn = None
    try:
        conn = get_db_connection()

        # Enforce uniqueness via database constraints and check basic availability
        # Optional pre-checks to provide faster feedback:
        cur = conn.execute("SELECT 1 FROM users WHERE email = ? OR username = ?", (payload.email, payload.username))
        existing = cur.fetchone()
        if existing:
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"message": "Email already in use or invalid data"})

        password_hash = hash_password(payload.password)
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (payload.email, payload.username, password_hash, utcnow_iso()),
        )
        return JSONResponse(status_code=status.HTTP_201_CREATED, content={"message": "Registration successful"})
    except sqlite3.IntegrityError:
        # Unique constraint violation or other integrity issues
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"message": "Email already in use or invalid data"})
    except sqlite3.Error:
        # Database error
        # Handle exceptional conditions per CWE-703: don't expose details
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"message": "Email already in use or invalid data"})
    except Exception:
        # Generic failure handling
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"message": "Email already in use or invalid data"})
    finally:
        if conn:
            conn.close()


@app.post("/login")
async def login(payload: LoginRequest):
    """
    Authenticate a user with email and password.
    """
    conn = None
    try:
        conn = get_db_connection()
        user = get_user_by_email(conn, payload.email)
        if not user:
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})

        if not verify_password(payload.password, user["password_hash"]):
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})

        token_data = {
            "uid": user["id"],
            "sub": user["username"],
            "email": user["email"],
        }
        token = create_access_token(data=token_data)
        return JSONResponse(status_code=status.HTTP_200_OK, content={"token": token, "message": "Login successful"})
    except sqlite3.Error:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})
    except Exception:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})
    finally:
        if conn:
            conn.close()


@app.post("/set_secret")
async def set_secret(payload: SetSecretRequest, auth_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Save a secret on the server using the username (in body) and bearer token in Authorization header.
    Enforces that the token user matches the provided username.
    """
    # Authorization check to prevent Insecure Direct Object Reference / improper authorization (CWE-863/284)
    if auth_user["username"] != payload.username:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

    conn = None
    try:
        conn = get_db_connection()
        user_row = get_user_by_username(conn, payload.username)
        if not user_row:
            # Should not happen as user was validated in token dependency, but handle gracefully (CWE-703)
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

        ok = upsert_secret(conn, user_row["id"], payload.secret)
        if not ok:
            # Fail gracefully
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})
        return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Secret has been set successfully"})
    except sqlite3.Error:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})
    except Exception:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})
    finally:
        if conn:
            conn.close()


@app.get("/get_secret")
async def get_secret(username: str = Query(...), auth_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Retrieve a secret based on the provided username. Requires bearer token.
    Enforces that token user matches the requested username.
    """
    if auth_user["username"] != username:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

    conn = None
    try:
        conn = get_db_connection()
        user_row = get_user_by_username(conn, username)
        if not user_row:
            # Return 200 with empty secret or could return 401; schema expects 401 for invalid token only,
            # so return empty to avoid leaking info.
            return JSONResponse(status_code=status.HTTP_200_OK, content={"secret": ""})

        secret_text = get_secret_for_user(conn, user_row["id"])
        if secret_text is None:
            return JSONResponse(status_code=status.HTTP_200_OK, content={"secret": ""})
        return JSONResponse(status_code=status.HTTP_200_OK, content={"secret": secret_text})
    except sqlite3.Error:
        # Graceful error handling (CWE-703)
        return JSONResponse(status_code=status.HTTP_200_OK, content={"secret": ""})
    except Exception:
        return JSONResponse(status_code=status.HTTP_200_OK, content={"secret": ""})
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000, without streaming responses
    uvicorn.run(app, host="0.0.0.0", port=5000)