import os
import re
import hmac
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, Request, HTTPException, status, Depends, Header, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, ValidationError
from passlib.hash import pbkdf2_sha256
import jwt  # pyjwt

# -----------------------------
# Configuration and Constants
# -----------------------------
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET or len(APP_SECRET) < 16:
    # Fallback to a random secret if not provided. In production, APP_SECRET must be set.
    # Using a random per-process secret means tokens become invalid across restarts.
    APP_SECRET = os.urandom(32).hex()

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # Token expiry

DB_PATH = "db.sqlite3"

USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")  # strict username policy
MAX_SECRET_LENGTH = 4096

# -----------------------------
# FastAPI Application
# -----------------------------
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


# -----------------------------
# Utility Functions
# -----------------------------
def get_db_connection() -> sqlite3.Connection:
    """
    Create a new SQLite connection with safe defaults.
    We create a connection per-request to avoid threading issues.
    """
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Apply PRAGMA settings for safer behavior
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA temp_store = MEMORY;")
    except sqlite3.DatabaseError:
        # Ignore pragma errors silently to avoid startup failure
        pass
    return conn


def init_db() -> None:
    """
    Initialize the database schema if it does not exist.
    """
    conn = get_db_connection()
    try:
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
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER NOT NULL UNIQUE,
                secret_text TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_secrets_user ON secrets(user_id);")
    finally:
        conn.close()


def safe_compare(a: str, b: str) -> bool:
    """
    Constant-time comparison to reduce timing attacks for sensitive string comparisons.
    """
    return hmac.compare_digest(a, b)


def create_access_token(username: str) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "type": "access",
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    # pyjwt returns string
    return token


def decode_token(token: str) -> dict:
    return jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret_text: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    # Use UPSERT to insert or update atomically
    conn.execute(
        """
        INSERT INTO secrets (user_id, secret_text, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            secret_text = excluded.secret_text,
            updated_at = excluded.updated_at
        """,
        (user_id, secret_text, now),
    )


def get_secret_for_user(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret_text FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if row is None:
        return None
    return row["secret_text"]


# -----------------------------
# Pydantic Models
# -----------------------------
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., min_length=3, max_length=64, examples=["user1"])
    password: str = Field(..., min_length=8, max_length=256, examples=["newUserPassword"])


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user@example.com"])
    password: str = Field(..., min_length=1, max_length=256, examples=["mySecretPassword"])


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, examples=["user1"])
    secret: str = Field(..., min_length=0, max_length=MAX_SECRET_LENGTH, examples=["mySecret"])


# -----------------------------
# Dependencies and Security
# -----------------------------
async def get_current_username(authorization: Optional[str] = Header(default=None)) -> str:
    """
    Extract and verify bearer token, return username (subject).
    """
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    parts = authorization.split()
    if len(parts) != 2 or not safe_compare(parts[0], "Bearer"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    token = parts[1]
    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        username = payload.get("sub")
        if not username or not isinstance(username, str):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    # Ensure user still exists
    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, username)
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    finally:
        conn.close()
    return username


# -----------------------------
# Exception Handlers
# -----------------------------
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Return consistent JSON shape with 'message' field where applicable
    message = exc.detail if isinstance(exc.detail, str) else "An error occurred"
    return JSONResponse(status_code=exc.status_code, content={"message": message})


@app.exception_handler(ValidationError)
async def validation_error_handler(request: Request, exc: ValidationError):
    # For body validation errors, return 400 with a generic message to avoid leaking details
    return JSONResponse(status_code=400, content={"message": "Invalid request data"})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Catch-all to avoid exposing stack traces and to satisfy CWE-703
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# -----------------------------
# Startup
# -----------------------------
@app.on_event("startup")
async def on_startup():
    init_db()


# -----------------------------
# Routes
# -----------------------------
@app.post("/register", status_code=201, tags=["Authentication"])
async def register(payload: RegisterRequest):
    email = payload.email.lower().strip()
    username = payload.username.strip()

    # Validate username pattern
    if not USERNAME_REGEX.fullmatch(username):
        return JSONResponse(
            status_code=400,
            content={"message": "Email already in use or invalid data"},
        )

    # Validate password policy (already min length via Pydantic)
    password = payload.password

    conn = get_db_connection()
    try:
        # Check uniqueness
        existing_email = get_user_by_email(conn, email)
        if existing_email is not None:
            return JSONResponse(
                status_code=400,
                content={"message": "Email already in use or invalid data"},
            )
        existing_username = get_user_by_username(conn, username)
        if existing_username is not None:
            return JSONResponse(
                status_code=400,
                content={"message": "Email already in use or invalid data"},
            )

        # Hash password securely
        password_hash = pbkdf2_sha256.hash(password)

        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, now),
        )
        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except sqlite3.IntegrityError:
        # In case of race condition on uniqueness
        return JSONResponse(
            status_code=400,
            content={"message": "Email already in use or invalid data"},
        )
    except sqlite3.DatabaseError:
        # Avoid leaking DB info
        return JSONResponse(status_code=500, content={"message": "Internal server error"})
    finally:
        conn.close()


@app.post("/login", tags=["Authentication"])
async def login(payload: LoginRequest):
    email = payload.email.lower().strip()
    password = payload.password

    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, email)
        if user is None:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        password_hash = user["password_hash"]
        if not pbkdf2_sha256.verify(password, password_hash):
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

        token = create_access_token(user["username"])
        return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})
    except sqlite3.DatabaseError:
        return JSONResponse(status_code=500, content={"message": "Internal server error"})
    finally:
        conn.close()


@app.post("/set_secret")
async def set_secret(payload: SetSecretRequest, current_username: str = Depends(get_current_username)):
    req_username = payload.username.strip()
    # Authorization: ensure token subject matches requested username
    if not safe_compare(current_username, req_username):
        # To avoid leaking whether username exists, use 401 per schema
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    secret_text = payload.secret
    if len(secret_text) > MAX_SECRET_LENGTH:
        raise HTTPException(status_code=400, detail="Invalid request data")

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, req_username)
        if user is None:
            # For safety: treat as unauthorized
            raise HTTPException(status_code=401, detail="Invalid authentication token")

        upsert_secret(conn, user["id"], secret_text)
        return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})
    except sqlite3.DatabaseError:
        return JSONResponse(status_code=500, content={"message": "Internal server error"})
    finally:
        conn.close()


@app.get("/get_secret")
async def get_secret(username: str = Query(..., min_length=3, max_length=64, example="user1"), current_username: str = Depends(get_current_username)):
    req_username = username.strip()
    # Authorization: ensure token subject matches requested username
    if not safe_compare(current_username, req_username):
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    # Validate username format
    if not USERNAME_REGEX.fullmatch(req_username):
        # Don't leak specifics; treat as unauthorized or bad request - schema expects 401 for auth failures
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, req_username)
        if user is None:
            # Conceal existence; return empty secret or 200 with empty payload? Schema expects 'secret' string.
            return JSONResponse(status_code=200, content={"secret": ""})
        secret_text = get_secret_for_user(conn, user["id"])
        if secret_text is None:
            secret_text = ""
        return JSONResponse(status_code=200, content={"secret": secret_text})
    except sqlite3.DatabaseError:
        return JSONResponse(status_code=500, content={"message": "Internal server error"})
    finally:
        conn.close()


# -----------------------------
# Run Server
# -----------------------------
if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)