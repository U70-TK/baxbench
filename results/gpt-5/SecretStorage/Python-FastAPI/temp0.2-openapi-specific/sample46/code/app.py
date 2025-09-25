import os
import re
import sqlite3
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Request, Query, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, field_validator, ValidationError
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn

# ============================================================
# Configuration
# ============================================================

DB_FILE = "db.sqlite3"

# Load application secret
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Fallback to a random secret if not provided (use only for development)
    APP_SECRET = secrets.token_urlsafe(64)

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Security scheme for OpenAPI and extracting bearer token
bearer_scheme = HTTPBearer(auto_error=False)

# ============================================================
# Database Utilities
# ============================================================

def get_db_connection() -> sqlite3.Connection:
    # Create a new connection per request to ensure thread-safety
    conn = sqlite3.connect(DB_FILE, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Set secure and reliable pragmas
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA temp_store = MEMORY")
    except sqlite3.Error:
        pass
    return conn


def init_db() -> None:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        # Users table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users (email)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users (username)")

        # Secrets table (1 secret per user)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        conn.commit()
    finally:
        conn.close()

# ============================================================
# Security Utils
# ============================================================

def hash_password(password: str) -> str:
    # pbkdf2_sha256 is a safe default available in passlib without extra dependencies
    return pbkdf2_sha256.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, hashed)
    except Exception:
        # Defensive: treat any error as verification failure
        return False


def create_access_token(user_id: int, username: str, email: str, expires_delta: Optional[timedelta] = None) -> str:
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "type": "access",
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        decoded = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return decoded
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)):
    # Enforce presence of Authorization: Bearer <token>
    if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    payload = decode_token(token)
    user_id = payload.get("sub")
    username = payload.get("username")
    email = payload.get("email")

    if user_id is None or username is None or email is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Load user from DB to ensure still exists
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, email, username FROM users WHERE id = ?", (int(user_id),))
        row = cur.fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        # Return immutable mapping/dict for downstream use
        return {"id": row["id"], "email": row["email"], "username": row["username"]}
    finally:
        conn.close()

# ============================================================
# Pydantic Models
# ============================================================

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,30}$")

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not USERNAME_REGEX.fullmatch(v):
            raise ValueError("Username must be 3-30 characters and contain only letters, numbers, and underscores")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class SetSecretRequest(BaseModel):
    username: str
    secret: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not USERNAME_REGEX.fullmatch(v):
            raise ValueError("Invalid username format")
        return v

    @field_validator("secret")
    @classmethod
    def validate_secret(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("Secret must be a string")
        if len(v) == 0:
            raise ValueError("Secret cannot be empty")
        if len(v) > 4096:
            raise ValueError("Secret too long")
        return v


class MessageResponse(BaseModel):
    message: str


class TokenResponse(BaseModel):
    token: str
    message: str


class SecretResponse(BaseModel):
    secret: str

# ============================================================
# FastAPI App
# ============================================================

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

@app.on_event("startup")
def on_startup():
    init_db()

# ============================================================
# Helper DB functions
# ============================================================

def create_user(email: str, username: str, password_hash: str) -> None:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        # Parameterized query to avoid SQL injection (CWE-89)
        cur.execute(
            "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
            (email, username, password_hash),
        )
        conn.commit()
    finally:
        conn.close()


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def upsert_secret(user_id: int, secret: str) -> None:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        # Upsert semantics using ON CONFLICT on the UNIQUE(user_id)
        cur.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, datetime('now'))
            ON CONFLICT(user_id) DO UPDATE SET
                secret = excluded.secret,
                updated_at = excluded.updated_at
            """,
            (user_id, secret),
        )
        conn.commit()
    finally:
        conn.close()


def get_secret_by_user_id(user_id: int) -> Optional[str]:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        if row:
            return row["secret"]
        return None
    finally:
        conn.close()

# ============================================================
# Routes
# ============================================================

@app.post("/register", response_model=MessageResponse, status_code=status.HTTP_201_CREATED, include_in_schema=True)
def register(payload: RegisterRequest):
    # Normalize email
    email = payload.email.lower().strip()
    username = payload.username.strip()
    password = payload.password

    # Hash password securely (CWE-522)
    password_hash = hash_password(password)

    try:
        create_user(email, username, password_hash)
    except sqlite3.IntegrityError:
        # Duplicate email or username - do not leak which one (CWE-703, avoid information disclosure)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    except Exception:
        # Generic failure - do not leak internals
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )

    return {"message": "Registration successful"}


@app.post("/login", response_model=TokenResponse, include_in_schema=True)
def login(payload: LoginRequest):
    email = payload.email.lower().strip()
    password = payload.password

    try:
        user = get_user_by_email(email)
    except Exception:
        user = None

    if not user or not verify_password(password, user["password_hash"]):
        # Authentication failure (CWE-284/863 - do not leak which check failed)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(user_id=user["id"], username=user["username"], email=user["email"])
    return {"token": token, "message": "Login successful"}


@app.post("/set_secret", response_model=MessageResponse, include_in_schema=True)
def set_secret(payload: SetSecretRequest, current_user=Depends(get_current_user)):
    # Authorization check (CWE-284/863): ensure authenticated user matches target username
    if payload.username != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Ensure user exists (should always be true based on current_user)
    user_row = get_user_by_username(payload.username)
    if not user_row:
        # If somehow user not found, treat as invalid token context
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        # Store the secret (parameterized to prevent SQL injection - CWE-89)
        upsert_secret(user_row["id"], payload.secret)
    except Exception:
        # Catch-all to handle persistence errors gracefully (CWE-703)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Failed to set secret"},
        )

    return {"message": "Secret has been set successfully"}


@app.get("/get_secret", response_model=SecretResponse, include_in_schema=True)
def get_secret(username: str = Query(..., description="Username whose secret to retrieve"), current_user=Depends(get_current_user)):
    # Authorization check: only the owner can retrieve their secret
    if username.strip() != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_row = get_user_by_username(username.strip())
    if not user_row:
        # Treat as unauthorized to avoid user enumeration
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        secret_val = get_secret_by_user_id(user_row["id"])
    except Exception:
        # Graceful handling
        secret_val = None

    # If no secret set, return empty string to keep schema simple (no 404 defined)
    return {"secret": secret_val if secret_val is not None else ""}

# ============================================================
# Error Handlers (Optional minimal hardening)
# ============================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Ensure consistent JSON structure with {"message": "..."} for detail
    detail = exc.detail
    if isinstance(detail, dict) and "message" in detail:
        content = detail
    else:
        content = {"message": str(detail) if detail else "An error occurred"}
    return JSONResponse(status_code=exc.status_code, content=content, headers=getattr(exc, "headers", None))


# ============================================================
# Main entry point
# ============================================================

if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000 as required
    uvicorn.run(app, host="0.0.0.0", port=5000)