import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, status, Request, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, ValidationError
from passlib.hash import pbkdf2_sha256
import jwt


DB_PATH = "db.sqlite3"
APP_TITLE = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"
JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = 60

# Get application secret from environment, fallback to a random one for development if not set
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate a strong random secret if not provided.
    # In production, APP_SECRET must be provided via environment.
    import secrets

    APP_SECRET = secrets.token_urlsafe(64)


app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

bearer_scheme = HTTPBearer(auto_error=False)


# ==========================
# Database utilities
# ==========================
def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30.0, isolation_level=None)
    # Protect against SQL injection; use only parameterized queries and avoid string concatenation.
    conn.row_factory = sqlite3.Row
    # Enable foreign keys
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db() -> None:
    conn = get_db_connection()
    try:
        # Use WAL for better concurrency
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# ==========================
# Models
# ==========================
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., min_length=3, max_length=30, pattern=r"^[A-Za-z0-9_]+$", example="user1")
    password: str = Field(..., min_length=8, max_length=128, example="newUserPassword")


class RegisterResponse(BaseModel):
    message: str = Field(..., example="Registration successful")


class ErrorMessage(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user@example.com")
    password: str = Field(..., min_length=8, max_length=128, example="mySecretPassword")


class LoginResponse(BaseModel):
    token: str = Field(..., example="jwt-token-abc123")
    message: str = Field(..., example="Login successful")


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=30, pattern=r"^[A-Za-z0-9_]+$", example="user1")
    secret: str = Field(..., min_length=1, max_length=8192, example="mySecret")


class SetSecretResponse(BaseModel):
    message: str = Field(..., example="Secret has been set successfully")


class GetSecretResponse(BaseModel):
    secret: str = Field(..., example="The secret associated with the provided details")


# ==========================
# Security helpers
# ==========================
def create_jwt_token(payload: Dict[str, Any], expires_minutes: int = JWT_EXP_MINUTES) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=expires_minutes)
    to_encode = {**payload, "iat": int(now.timestamp()), "exp": int(exp.timestamp()), "iss": APP_TITLE}
    token = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_jwt_token(token: str) -> Dict[str, Any]:
    try:
        decoded = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM], options={"require": ["exp", "iat"]})
        return decoded
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


def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)) -> Dict[str, Any]:
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    token = credentials.credentials
    claims = decode_jwt_token(token)
    username = claims.get("sub")
    uid = claims.get("uid")
    if not username or uid is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    # Ensure user exists and is consistent
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT id, email, username FROM users WHERE id = ? AND username = ?", (uid, username)).fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        return {"id": row["id"], "email": row["email"], "username": row["username"], "claims": claims}
    finally:
        conn.close()


# ==========================
# Error handling
# ==========================
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Avoid leaking internal errors; return a generic message
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# ==========================
# Helpers
# ==========================
def password_is_strong(password: str) -> bool:
    # Basic strength checks: length >= 8, has letters and digits
    has_letter = any(c.isalpha() for c in password)
    has_digit = any(c.isdigit() for c in password)
    return len(password) >= 8 and has_letter and has_digit


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,)).fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?", (username,)).fetchone()


# ==========================
# Routes
# ==========================
@app.post(
    "/register",
    response_model=RegisterResponse,
    responses={
        201: {"description": "Successful registration", "model": RegisterResponse},
        400: {"description": "Bad Request", "model": ErrorMessage},
    },
    status_code=status.HTTP_201_CREATED,
    summary="User registration",
    tags=["Authentication"],
)
def register(payload: RegisterRequest):
    # Validate password strength to avoid weak credentials (CWE-522)
    if not password_is_strong(payload.password):
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
    # Hash the password securely using PBKDF2-SHA256 (from passlib) (CWE-522)
    password_hash = pbkdf2_sha256.hash(payload.password)

    conn = get_db_connection()
    try:
        # Ensure email and username uniqueness and prevent SQL injection with parameterized queries (CWE-89)
        existing_email = conn.execute("SELECT 1 FROM users WHERE email = ?", (payload.email,)).fetchone()
        existing_username = conn.execute("SELECT 1 FROM users WHERE username = ?", (payload.username,)).fetchone()
        if existing_email or existing_username:
            raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

        now_iso = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (payload.email, payload.username, password_hash, now_iso),
        )
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Handle rare DB edge cases gracefully (CWE-703)
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
    finally:
        conn.close()


@app.post(
    "/login",
    response_model=LoginResponse,
    responses={
        200: {"description": "Successful login", "model": LoginResponse},
        401: {"description": "Unauthorized", "model": ErrorMessage},
    },
    summary="User login",
    tags=["Authentication"],
)
def login(payload: LoginRequest):
    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, payload.email)
        if not user:
            # Do not reveal whether email exists (CWE-522)
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
        # Verify password securely (CWE-522)
        if not pbkdf2_sha256.verify(payload.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})

        token = create_jwt_token(
            payload={"sub": user["username"], "uid": user["id"], "email": user["email"]},
            expires_minutes=JWT_EXP_MINUTES,
        )
        return {"token": token, "message": "Login successful"}
    finally:
        conn.close()


@app.post(
    "/set_secret",
    response_model=SetSecretResponse,
    responses={
        200: {"description": "Secret set successfully", "model": SetSecretResponse},
        401: {"description": "Unauthorized", "model": ErrorMessage},
    },
    summary="Set secret",
    description="Save a secret on the server using the username and the secret text. Requires a valid Bearer token.",
)
def set_secret(payload: SetSecretRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    # Authorization check: ensure the token user matches the requested username (CWE-284, CWE-863)
    if current_user["username"] != payload.username:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, payload.username)
        if not user:
            # Avoid disclosure of user existence
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

        now_iso = datetime.now(timezone.utc).isoformat()
        # Upsert secret safely using parameterized queries (CWE-89)
        # Try update first
        cur = conn.execute(
            "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
            (payload.secret, now_iso, user["id"]),
        )
        if cur.rowcount == 0:
            # Insert if no existing secret
            conn.execute(
                "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
                (user["id"], payload.secret, now_iso),
            )

        return {"message": "Secret has been set successfully"}
    finally:
        conn.close()


@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
    responses={
        200: {"description": "Secret retrieved successfully", "model": GetSecretResponse},
        401: {"description": "Unauthorized", "model": ErrorMessage},
    },
    summary="Get secret",
    description="Retrieve a secret based on the provided username. Requires a valid Bearer token.",
)
def get_secret(username: str = Query(..., min_length=3, max_length=30, pattern=r"^[A-Za-z0-9_]+$", example="user1"), current_user: Dict[str, Any] = Depends(get_current_user)):
    # Authorization check: ensure the token user matches the requested username (CWE-284, CWE-863)
    if current_user["username"] != username:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, username)
        if not user:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

        row = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user["id"],)).fetchone()
        if not row:
            # For consistency, return empty secret if none set
            return {"secret": ""}
        return {"secret": row["secret"]}
    finally:
        conn.close()


if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000 (no streaming responses)
    uvicorn.run(app, host="0.0.0.0", port=5000)