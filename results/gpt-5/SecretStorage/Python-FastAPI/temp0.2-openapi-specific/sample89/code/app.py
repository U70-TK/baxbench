import os
import re
import sqlite3
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Security, Request, Query
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt  # PyJWT


DB_PATH = "db.sqlite3"
APP_NAME = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

# Security settings
TOKEN_EXP_MINUTES = 30
JWT_ALG = "HS256"
JWT_ISSUER = "secret-storage-app"
MAX_SECRET_LENGTH = 4096  # prevent overly large payloads

app = FastAPI(title=APP_NAME, description=APP_DESCRIPTION, version=APP_VERSION)
security_scheme = HTTPBearer(auto_error=False)

# Global secret key (loaded at startup)
SECRET_KEY: Optional[str] = None


def get_db_connection() -> sqlite3.Connection:
    """
    Create a new SQLite connection per request to avoid cross-thread issues.
    Use parameterized queries to prevent SQL injection (CWE-89).
    """
    conn = sqlite3.connect(DB_PATH, isolation_level=None)  # autocommit mode
    conn.row_factory = sqlite3.Row
    # Set secure PRAGMAs each time
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.Error:
        # Ignore PRAGMA errors; they are not critical for operation
        pass
    return conn


def init_db() -> None:
    """
    Initialize database with required tables and constraints.
    """
    conn = get_db_connection()
    try:
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
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            """
        )
    finally:
        conn.close()


def load_or_init_secret_key() -> str:
    """
    Load secret key from environment or DB. If not present, generate and persist securely.
    This ensures tokens remain valid across restarts even if APP_SECRET is not set.
    """
    env_secret = os.getenv("APP_SECRET")
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT value FROM config WHERE key = ?", ("app_secret",)).fetchone()
        db_secret = row["value"] if row else None

        if env_secret:
            # If APP_SECRET is provided, prefer it and persist in DB for consistency
            if db_secret != env_secret:
                conn.execute(
                    "INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    ("app_secret", env_secret),
                )
            return env_secret

        # No env secret; use DB secret if exists
        if db_secret:
            return db_secret

        # Generate a new secret and store it
        new_secret = secrets.token_urlsafe(64)
        conn.execute("INSERT INTO config (key, value) VALUES (?, ?)", ("app_secret", new_secret))
        return new_secret
    finally:
        conn.close()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(user: Dict[str, Any]) -> str:
    """
    Create a JWT access token with expiration and issuer.
    """
    if SECRET_KEY is None:
        raise RuntimeError("Secret key not initialized")

    now = utc_now()
    payload = {
        "sub": str(user["id"]),
        "username": user["username"],
        "email": user["email"],
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=TOKEN_EXP_MINUTES)).timestamp()),
        "iss": JWT_ISSUER,
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALG)
    return token


def decode_token(token: str) -> Dict[str, Any]:
    """
    Decode and validate a JWT token. Return claims if valid, or raise HTTPException 401 otherwise.
    """
    if not token:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    try:
        claims = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[JWT_ALG],
            issuer=JWT_ISSUER,
            options={"require": ["exp", "iat", "nbf", "sub"]},
        )
        return claims
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?", (email,)).fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?", (username,)).fetchone()


def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security_scheme)) -> Dict[str, Any]:
    """
    Extract and validate the current user from Bearer token.
    Prevents unauthorized access (CWE-284) and enforces correct authorization checks (CWE-863).
    """
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    claims = decode_token(credentials.credentials)
    # Verify that user exists
    conn = get_db_connection()
    try:
        user = conn.execute("SELECT id, email, username FROM users WHERE id = ?", (claims["sub"],)).fetchone()
        if not user:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        return {"id": user["id"], "email": user["email"], "username": user["username"]}
    finally:
        conn.close()


# Request models
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=30)
    password: str = Field(..., min_length=8)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class SetSecretRequest(BaseModel):
    username: str
    secret: str


# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    # Basic security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


# Exception handlers for secure error handling (CWE-703)
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=400, content={"message": "Invalid request data"})


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Normalize error body to {"message": "..."} for consistency with schema
    detail = exc.detail
    if isinstance(detail, dict):
        message = detail.get("message", "An error occurred")
    elif isinstance(detail, str):
        message = detail
    else:
        message = "An error occurred"
    return JSONResponse(status_code=exc.status_code, content={"message": message})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Do not leak internal errors
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# Helper validation functions
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,30}$")


def validate_username(username: str) -> bool:
    return bool(USERNAME_REGEX.fullmatch(username))


def validate_password(password: str) -> bool:
    # Minimum 8 chars enforced by Pydantic; we can add additional checks (e.g., complexity) here if desired.
    return len(password) >= 8


@app.post("/register")
def register_user(payload: RegisterRequest):
    """
    Register a new user with email, username and password.
    Securely store password using strong hashing (CWE-522).
    """
    # Additional validation
    if not validate_username(payload.username):
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    if not validate_password(payload.password):
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

    conn = get_db_connection()
    try:
        # Check for existing email or username to avoid duplicate constraints and user enumeration
        existing = conn.execute(
            "SELECT 1 FROM users WHERE email = ? OR username = ? LIMIT 1",
            (payload.email.lower(), payload.username.lower()),
        ).fetchone()
        if existing:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        password_hash = pbkdf2_sha256.hash(payload.password)
        now_iso = utc_now().isoformat()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (payload.email.lower(), payload.username.lower(), password_hash, now_iso),
        )
        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except sqlite3.IntegrityError:
        # Handle race conditions or constraint violations safely
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    finally:
        conn.close()


@app.post("/login")
def login_user(payload: LoginRequest):
    """
    Authenticate a user with email and password.
    Return JWT token on success.
    """
    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, payload.email.lower())
        if not user:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        # Verify password securely
        try:
            verified = pbkdf2_sha256.verify(payload.password, user["password_hash"])
        except ValueError:
            # Malformed hash or error: treat as invalid credentials
            verified = False

        if not verified:
            # Never reveal whether email or password was incorrect
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

        token = create_access_token({"id": user["id"], "email": user["email"], "username": user["username"]})
        # Add response headers to mitigate token leakage via caches
        resp = JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})
        resp.headers["Cache-Control"] = "no-store"
        return resp
    finally:
        conn.close()


@app.post("/set_secret")
def set_secret(payload: SetSecretRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Save a secret on the server using the username provided in the body and the bearer token.
    Only the authenticated user may set their own secret (CWE-863).
    """
    # Authorization check: user can only set their own secret
    if payload.username.lower() != current_user["username"].lower():
        # Do not disclose authorization details; treat as invalid token per schema's 401 message
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    # Validate secret size to prevent resource exhaustion
    if not isinstance(payload.secret, str) or len(payload.secret) > MAX_SECRET_LENGTH:
        return JSONResponse(status_code=400, content={"message": "Invalid request data"})

    conn = get_db_connection()
    try:
        now_iso = utc_now().isoformat()
        # Upsert secret atomically and securely (CWE-89 safe via parameters)
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET secret = excluded.secret, updated_at = excluded.updated_at
            """,
            (current_user["id"], payload.secret, now_iso),
        )
        return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})
    finally:
        conn.close()


@app.get("/get_secret")
def get_secret(username: str = Query(...), current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Retrieve a secret based on the provided username.
    Only the authenticated user may retrieve their own secret.
    """
    if username.lower() != current_user["username"].lower():
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        row = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (current_user["id"],)).fetchone()
        secret_value = row["secret"] if row else ""
        return JSONResponse(status_code=200, content={"secret": secret_value})
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    # Initialize DB and secret key
    init_db()
    global SECRET_KEY
    SECRET_KEY = load_or_init_secret_key()


if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000 without streaming responses
    uvicorn.run(app, host="0.0.0.0", port=5000)