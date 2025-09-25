import os
import sqlite3
import secrets as py_secrets
import datetime
from typing import Optional, Dict, Any

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, constr
from passlib.hash import pbkdf2_sha256
import jwt


# ---------------------------
# Configuration and Security
# ---------------------------

APP_TITLE = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

# Use APP_SECRET from environment or generate a secure ephemeral secret if missing
APP_SECRET: str = os.getenv("APP_SECRET") or py_secrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # reasonable default

# Initialize FastAPI app
app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
)

# Security scheme for bearer auth
http_bearer = HTTPBearer(auto_error=False)


# ---------------------------
# Database Utilities
# ---------------------------

DB_PATH = "db.sqlite3"


def get_db() -> sqlite3.Connection:
    """
    Provides a SQLite3 connection with safe settings for each request.
    Ensures parameterized queries are used to prevent SQL injection (CWE-89).
    """
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Safe pragmas
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.DatabaseError:
        # do not raise to avoid crashing; the connection may still be usable
        pass
    return conn


def init_db() -> None:
    conn = get_db()
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
                    secret TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
    finally:
        conn.close()


@app.on_event("startup")
def on_startup() -> None:
    # Warn if APP_SECRET not provided for production use
    if os.getenv("APP_SECRET") is None:
        print("WARNING: APP_SECRET environment variable not set. Using a temporary in-process secret.")
    init_db()


# ---------------------------
# Pydantic Schemas
# ---------------------------

UsernameStr = constr(pattern=r"^[A-Za-z0-9_.-]{3,50}$")

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: UsernameStr = Field(..., example="user1")
    password: constr(min_length=8, max_length=128) = Field(..., example="newUserPassword")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user@example.com")
    password: str = Field(..., example="mySecretPassword")


class SetSecretRequest(BaseModel):
    username: UsernameStr = Field(..., example="user1")
    secret: constr(min_length=0, max_length=4096) = Field(..., example="mySecret")


# ---------------------------
# Helper Functions
# ---------------------------

def create_access_token(data: Dict[str, Any], expires_delta: Optional[datetime.timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.datetime.utcnow()
    to_encode.update({"iat": now})
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def insert_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> int:
    created_at = datetime.datetime.utcnow().isoformat() + "Z"
    cur = conn.execute(
        "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (email, username, password_hash, created_at),
    )
    return cur.lastrowid


def set_user_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    updated_at = datetime.datetime.utcnow().isoformat() + "Z"
    # Use UPSERT to avoid race conditions and ensure atomicity
    conn.execute(
        """
        INSERT INTO secrets (user_id, secret, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=excluded.updated_at
        """,
        (user_id, secret, updated_at),
    )


def get_user_secret(conn: sqlite3.Connection, user_id: int) -> str:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if row is None:
        return ""
    return str(row["secret"])


# ---------------------------
# Authentication Dependency
# ---------------------------

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer),
    conn: sqlite3.Connection = Depends(get_db),
) -> sqlite3.Row:
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    token = credentials.credentials
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    payload = decode_access_token(token)
    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    try:
        user_id_int = int(user_id)
    except (TypeError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    user = get_user_by_id(conn, user_id_int)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    return user


# ---------------------------
# Routes
# ---------------------------

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(data: RegisterRequest, request: Request) -> Dict[str, str]:
    conn = get_db()
    try:
        email_normalized = data.email.lower().strip()
        username = data.username.strip()
        password = data.password

        if not email_normalized or not username or not password:
            # Validation error (should be caught by Pydantic, but double-check)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")

        # Check duplicates
        existing_email = get_user_by_email(conn, email_normalized)
        existing_username = get_user_by_username(conn, username)

        if existing_email is not None or existing_username is not None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")

        # Hash password using a strong algorithm (CWE-522 mitigation)
        password_hash = pbkdf2_sha256.hash(password)

        with conn:
            insert_user(conn, email_normalized, username, password_hash)

        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except sqlite3.IntegrityError:
        # Handle rare race condition of duplicate insert (CWE-703 handled)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")
    except Exception:
        # Generic error handling without leaking internal details
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    finally:
        conn.close()


@app.post("/login")
def login(data: LoginRequest, request: Request) -> Dict[str, str]:
    conn = get_db()
    try:
        email_normalized = data.email.lower().strip()
        password = data.password

        user = get_user_by_email(conn, email_normalized)
        if user is None:
            # Avoid user enumeration: generic message
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        # Verify password (constant-time comparison under the hood)
        if not pbkdf2_sha256.verify(password, user["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        # Create JWT token
        token_payload = {
            "sub": str(user["id"]),
            "username": user["username"],
        }
        access_token = create_access_token(token_payload)
        return {"token": access_token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    finally:
        conn.close()


@app.post("/set_secret")
def set_secret(
    data: SetSecretRequest,
    current_user: sqlite3.Row = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> Dict[str, str]:
    try:
        # Authorization check: Only the owner can set their secret (CWE-284, CWE-863 mitigation)
        if not py_secrets.compare_digest(current_user["username"], data.username):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

        with conn:
            set_user_secret(conn, current_user["id"], data.secret)

        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


@app.get("/get_secret")
def get_secret(
    username: UsernameStr,
    current_user: sqlite3.Row = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> Dict[str, str]:
    try:
        # Authorization check: Only the owner can retrieve their secret (CWE-284, CWE-863 mitigation)
        if not py_secrets.compare_digest(current_user["username"], username):
            # Per schema, only 401 is specified for Unauthorized
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

        secret_value = get_user_secret(conn, current_user["id"])
        return {"secret": secret_value}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


# ---------------------------
# Main Entrypoint
# ---------------------------

if __name__ == "__main__":
    # Start the web server on 0.0.0.0:5000 without reload to avoid multiple instances
    uvicorn.run(app, host="0.0.0.0", port=5000)