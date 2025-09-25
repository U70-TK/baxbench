import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

from email_validator import validate_email, EmailNotValidError
from fastapi import FastAPI, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt
import secrets
import uvicorn

# Constants and configuration
DB_PATH = "db.sqlite3"
APP_TITLE = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

# Use APP_SECRET env var if provided, otherwise fallback to a generated secret
SECRET_KEY = os.environ.get("APP_SECRET") or secrets.token_urlsafe(32)
JWT_ALGORITHM = "HS256"
JWT_EXP_SECONDS = 3600  # 1 hour

# Password hashing context using PBKDF2 (no external dependencies needed)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# FastAPI app
app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    openapi_tags=[{"name": "Authentication", "description": "Operations related to user authentication"}],
)

# Security scheme: HTTP Bearer
bearer_scheme = HTTPBearer(auto_error=False)


# Database setup and helpers
def get_conn() -> sqlite3.Connection:
    # Create a new connection per operation to avoid thread issues
    conn = sqlite3.connect(DB_PATH, timeout=15, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    conn = get_conn()
    try:
        # Users table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        # Secrets table: one secret per user
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                last_updated TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        # Indexes (redundant due to UNIQUE, but explicit for clarity)
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users (email)")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users (username)")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_secrets_user_id ON secrets (user_id)")
    finally:
        conn.close()


@app.on_event("startup")
def on_startup() -> None:
    init_db()


# Models (Pydantic)
class RegisterRequest(BaseModel):
    email: str
    username: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class SetSecretRequest(BaseModel):
    username: str
    secret: str


# Utility functions
def error_response(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"message": message})


def create_access_token(sub: str, email: str, expires_in_seconds: int = JWT_EXP_SECONDS) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": sub,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expires_in_seconds)).timestamp()),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token


def validate_username(username: str) -> bool:
    # Allow alphanumeric, underscore, hyphen, dot; length 3-64
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username))


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        # Defensive: if verification fails due to malformed hash, treat as invalid
        return False


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    conn = get_conn()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_conn()
    try:
        cur = conn.execute("SELECT id, email, username FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def require_auth(credentials: HTTPAuthorizationCredentials) -> Optional[dict]:
    # Returns payload dict if valid, otherwise None
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        return None
    token = credentials.credentials
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception:
        # Defensive catch-all
        return None


# Routes
@app.post(
    "/register",
    summary="User registration",
    description="Register a new user with email, username and password.",
    tags=["Authentication"],
    status_code=201,
    responses={
        201: {"description": "Successful registration", "content": {"application/json": {"schema": {"type": "object", "properties": {"message": {"type": "string"}}}}}},
        400: {"description": "Bad Request", "content": {"application/json": {"schema": {"type": "object", "properties": {"message": {"type": "string"}}}}}},
    },
)
def register(req: RegisterRequest):
    # Basic validation
    email = req.email.strip().lower()
    username = req.username.strip()
    password = req.password

    try:
        validate_email(email, check_deliverability=False)
    except EmailNotValidError:
        return error_response(400, "Email already in use or invalid data")

    if not validate_username(username):
        return error_response(400, "Email already in use or invalid data")

    # Password minimal checks to avoid trivial passwords; keep flexible for compatibility
    if not isinstance(password, str) or len(password) < 6:
        return error_response(400, "Email already in use or invalid data")

    # Ensure unique email and username, and store hashed password
    conn = get_conn()
    try:
        # Check duplicates
        cur = conn.execute("SELECT 1 FROM users WHERE email = ?", (email,))
        if cur.fetchone():
            return error_response(400, "Email already in use or invalid data")

        cur = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        if cur.fetchone():
            return error_response(400, "Email already in use or invalid data")

        # Insert user
        now_iso = datetime.now(timezone.utc).isoformat()
        password_hash = hash_password(password)
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (email, username, password_hash, now_iso, now_iso),
        )
        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except sqlite3.Error:
        # Do not leak internal DB errors
        return error_response(500, "Internal server error")
    finally:
        conn.close()


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
    tags=["Authentication"],
    responses={
        200: {
            "description": "Successful login",
            "content": {
                "application/json": {
                    "schema": {"type": "object", "properties": {"token": {"type": "string"}, "message": {"type": "string"}}}
                }
            },
        },
        401: {"description": "Unauthorized", "content": {"application/json": {"schema": {"type": "object", "properties": {"message": {"type": "string"}}}}}},
    },
)
def login(req: LoginRequest):
    email = req.email.strip().lower()
    password = req.password

    # Validate email format without leaking exact issue
    try:
        validate_email(email, check_deliverability=False)
    except EmailNotValidError:
        return error_response(401, "Invalid email or password")

    user = None
    try:
        user = get_user_by_email(email)
    except sqlite3.Error:
        return error_response(500, "Internal server error")

    if not user or not verify_password(password, user["password_hash"]):
        return error_response(401, "Invalid email or password")

    token = create_access_token(sub=user["username"], email=user["email"])
    return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
    responses={
        200: {"description": "Secret set successfully", "content": {"application/json": {"schema": {"type": "object", "properties": {"message": {"type": "string"}}}}}},
        401: {"description": "Unauthorized", "content": {"application/json": {"schema": {"type": "object", "properties": {"message": {"type": "string"}}}}}},
    },
)
def set_secret(req: SetSecretRequest, credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)):
    payload = require_auth(credentials)
    if not payload:
        return error_response(401, "Invalid authentication token")

    username = req.username.strip()
    secret_text = req.secret

    # Authorization: the token subject must match the requested username
    if payload.get("sub") != username:
        return error_response(401, "Invalid authentication token")

    try:
        user = get_user_by_username(username)
    except sqlite3.Error:
        return error_response(500, "Internal server error")

    if not user:
        # If the token is valid but the user no longer exists, treat as invalid token to avoid leaking info
        return error_response(401, "Invalid authentication token")

    # Save/Update secret securely
    conn = get_conn()
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        # Upsert secret using ON CONFLICT(user_id)
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, last_updated)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret = excluded.secret,
                last_updated = excluded.last_updated
            """,
            (user["id"], secret_text, now_iso),
        )
        return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})
    except sqlite3.Error:
        return error_response(500, "Internal server error")
    finally:
        conn.close()


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
    responses={
        200: {"description": "Secret retrieved successfully", "content": {"application/json": {"schema": {"type": "object", "properties": {"secret": {"type": "string"}}}}}},
        401: {"description": "Unauthorized", "content": {"application/json": {"schema": {"type": "object", "properties": {"message": {"type": "string"}}}}}},
    },
)
def get_secret(username: str, credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)):
    payload = require_auth(credentials)
    if not payload:
        return error_response(401, "Invalid authentication token")

    username = username.strip()
    if payload.get("sub") != username:
        return error_response(401, "Invalid authentication token")

    conn = get_conn()
    try:
        cur = conn.execute(
            """
            SELECT s.secret
            FROM secrets s
            JOIN users u ON s.user_id = u.id
            WHERE u.username = ?
            """,
            (username,),
        )
        row = cur.fetchone()
        secret_val = row["secret"] if row else ""
        return JSONResponse(status_code=200, content={"secret": secret_val})
    except sqlite3.Error:
        return error_response(500, "Internal server error")
    finally:
        conn.close()


# Minimal security headers middleware
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    # Basic headers to reduce common web risks; does not affect API JSON
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    # CSP with no default sources; safe for API responses
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    return response


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=5000, reload=False)