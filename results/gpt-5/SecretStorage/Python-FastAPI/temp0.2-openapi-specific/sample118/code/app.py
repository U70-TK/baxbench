import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import jwt  # pyjwt
from fastapi import FastAPI, Depends, status, Body, Query
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import uvicorn


# ----------------------------
# Configuration and utilities
# ----------------------------

APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Fallback to a random secret if not provided; suitable for local/dev use.
    # In production, ensure APP_SECRET is set.
    import secrets as _secrets

    APP_SECRET = _secrets.token_urlsafe(64)

DB_PATH = "db.sqlite3"


def get_db_connection() -> sqlite3.Connection:
    # Create a new connection per operation to avoid threading issues.
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Enforce foreign key constraints.
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    conn = get_db_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


# ----------------------------
# Security dependencies
# ----------------------------

bearer_scheme = HTTPBearer(auto_error=False)


def decode_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        return payload
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


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Dict[str, Any]:
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    payload = decode_token(credentials.credentials)
    # Basic sanity checks on payload contents
    if not isinstance(payload, dict) or "sub" not in payload or "username" not in payload or "email" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    return payload


# ----------------------------
# Pydantic models
# ----------------------------

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., examples=["user1"])
    password: str = Field(..., min_length=8, examples=["newUserPassword"])


class RegisterResponse(BaseModel):
    message: str = Field(..., examples=["Registration successful"])


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user@example.com"])
    password: str = Field(..., min_length=8, examples=["mySecretPassword"])


class LoginResponse(BaseModel):
    token: str = Field(..., examples=["jwt-token-abc123"])
    message: str = Field(..., examples=["Login successful"])


class SetSecretRequest(BaseModel):
    username: str = Field(..., examples=["user1"])
    secret: str = Field(..., min_length=1, max_length=4096, examples=["mySecret"])


class SetSecretResponse(BaseModel):
    message: str = Field(..., examples=["Secret has been set successfully"])


class GetSecretResponse(BaseModel):
    secret: str = Field(..., examples=["The secret associated with the provided details"])


# ----------------------------
# Helper functions
# ----------------------------

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,50}$")


def is_valid_username(username: str) -> bool:
    return bool(USERNAME_REGEX.fullmatch(username))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def find_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def find_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> int:
    ts = now_iso()
    cur = conn.execute(
        "INSERT INTO users (email, username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (email, username, password_hash, ts, ts),
    )
    conn.commit()
    return cur.lastrowid


def set_user_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    ts = now_iso()
    # Upsert: if exists update, else insert
    existing = conn.execute("SELECT id FROM secrets WHERE user_id = ?", (user_id,)).fetchone()
    if existing:
        conn.execute(
            "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
            (secret, ts, user_id),
        )
    else:
        conn.execute(
            "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
            (user_id, secret, ts),
        )
    conn.commit()


def get_user_secret(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if row:
        return row["secret"]
    return None


def create_access_token(sub: int, email: str, username: str, expires_in_minutes: int = 60) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_in_minutes)
    payload = {
        "sub": sub,
        "email": email,
        "username": username,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm="HS256")
    return token


# ----------------------------
# FastAPI app and routes
# ----------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


@app.on_event("startup")
def startup_event():
    # Initialize database schema
    init_db()


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    # Ensure 400/401 responses match expected schema {"message": "..."}
    if exc.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_401_UNAUTHORIZED):
        detail = exc.detail
        if isinstance(detail, dict) and "message" in detail:
            content = detail
        else:
            content = {"message": str(detail)}
        return JSONResponse(status_code=exc.status_code, content=content)
    # Default fallback for other HTTPExceptions
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc: Exception):
    # Generic error handler to avoid leaking internal details (CWE-703)
    return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"detail": "Internal server error"})


@app.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    response_model=RegisterResponse,
    tags=["Authentication"],
)
def register(data: RegisterRequest = Body(...)):
    email_normalized = data.email.lower().strip()
    username_normalized = data.username.strip()

    if not is_valid_username(username_normalized):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )

    # Hash password securely (CWE-522)
    password_hash = pbkdf2_sha256.hash(data.password)

    conn = get_db_connection()
    try:
        # Check uniqueness (avoid user enumeration)
        existing_email = find_user_by_email(conn, email_normalized)
        existing_username = find_user_by_username(conn, username_normalized)
        if existing_email or existing_username:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )

        create_user(conn, email_normalized, username_normalized, password_hash)
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # In case of race condition, still return same 400 message
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    finally:
        conn.close()


@app.post(
    "/login",
    response_model=LoginResponse,
    tags=["Authentication"],
)
def login(data: LoginRequest = Body(...)):
    email_normalized = data.email.lower().strip()
    conn = get_db_connection()
    try:
        user = find_user_by_email(conn, email_normalized)
        if not user:
            # Generic 401 message (avoid user enumeration)
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
            )
        # Verify password (constant-time via passlib)
        if not pbkdf2_sha256.verify(data.password, user["password_hash"]):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
            )
        token = create_access_token(sub=int(user["id"]), email=user["email"], username=user["username"])
        return {"token": token, "message": "Login successful"}
    finally:
        conn.close()


@app.post(
    "/set_secret",
    response_model=SetSecretResponse,
)
def set_secret(
    payload: SetSecretRequest = Body(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    # Authorization check: prevent horizontal privilege escalation (CWE-284, CWE-863)
    if payload.username.strip() != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    # Validate secret content length (already constrained by model) and sanitize input implicitly via parameterization
    conn = get_db_connection()
    try:
        # Load user by username from DB to get user_id
        user = find_user_by_username(conn, current_user["username"])
        if not user:
            # If token says user exists but DB doesn't, treat as invalid token
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        # Store secret securely using parameterized SQL (CWE-89)
        set_user_secret(conn, int(user["id"]), payload.secret)
        return {"message": "Secret has been set successfully"}
    finally:
        conn.close()


@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
)
def get_secret(
    username: str = Query(..., examples=["user1"]),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    # Authorization: user can only access their own secret (CWE-284, CWE-863)
    username_normalized = username.strip()
    if username_normalized != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    conn = get_db_connection()
    try:
        user = find_user_by_username(conn, current_user["username"])
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        secret = get_user_secret(conn, int(user["id"]))
        # If no secret set, return empty string as a safe default
        return {"secret": secret if secret is not None else ""}
    finally:
        conn.close()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)