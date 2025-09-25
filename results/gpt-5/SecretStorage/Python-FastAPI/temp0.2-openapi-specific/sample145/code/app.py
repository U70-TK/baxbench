import os
import re
import sqlite3
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Generator

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Request, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from passlib.hash import pbkdf2_sha256
from email_validator import validate_email, EmailNotValidError
import jwt

# -----------------------------
# Configuration and Constants
# -----------------------------

DB_PATH = "db.sqlite3"
JWT_ALG = "HS256"
DEFAULT_TOKEN_EXPIRE_MINUTES = 60

APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate an ephemeral secret if not provided; for production, always set APP_SECRET.
    APP_SECRET = pysecrets.token_urlsafe(64)
    print("WARNING: APP_SECRET is not set. Generated a temporary secret key. Tokens will be invalid after restart.")

# -----------------------------
# Database Utilities
# -----------------------------

def get_db_connection() -> sqlite3.Connection:
    # Create a new connection per request to avoid threading issues.
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Recommended pragmas for integrity and performance trade-offs.
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
    except sqlite3.Error:
        # Even if PRAGMAs fail, continue with safe defaults.
        pass
    return conn

def init_db() -> None:
    conn = get_db_connection()
    try:
        with conn:
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
                    secret TEXT,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
                CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
                """
            )
    finally:
        conn.close()

def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = get_db_connection()
    try:
        yield conn
    finally:
        conn.close()

# -----------------------------
# Security / Auth Utilities
# -----------------------------

bearer_scheme = HTTPBearer(auto_error=False)

def create_access_token(sub: str, uid: int, email: str, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(timezone.utc)
    exp = now + (expires_delta if expires_delta else timedelta(minutes=DEFAULT_TOKEN_EXPIRE_MINUTES))
    payload = {
        "sub": sub,
        "uid": uid,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "nbf": int(now.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALG)
    return token

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALG])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

async def get_current_claims(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)) -> dict:
    if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    token = credentials.credentials
    claims = decode_token(token)
    return claims

# -----------------------------
# Pydantic Models
# -----------------------------

class RegisterRequest(BaseModel):
    email: str = Field(..., example="newuser@example.com")
    username: str = Field(..., example="user1")
    password: str = Field(..., example="newUserPassword")

class RegisterResponse(BaseModel):
    message: str = Field(..., example="Registration successful")

class ErrorMessage(BaseModel):
    message: str

class LoginRequest(BaseModel):
    email: str = Field(..., example="user@example.com")
    password: str = Field(..., example="mySecretPassword")

class LoginResponse(BaseModel):
    token: str = Field(..., example="jwt-token-abc123")
    message: str = Field(..., example="Login successful")

class SetSecretRequest(BaseModel):
    username: str = Field(..., example="user1")
    secret: str = Field(..., example="mySecret")

class SetSecretResponse(BaseModel):
    message: str = Field(..., example="Secret has been set successfully")

class GetSecretResponse(BaseModel):
    secret: str

# -----------------------------
# FastAPI App and Error Handlers
# -----------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

@app.on_event("startup")
def on_startup():
    init_db()

# Handle generic unexpected errors to avoid leaking details and satisfy CWE-703
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # For security, do not expose internal details
    return JSONResponse(status_code=500, content={"message": "Internal server error"})

# -----------------------------
# Helpers
# -----------------------------

USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_.-]{3,50}$")

def normalize_email(email: str) -> str:
    return email.strip().lower()

def validate_registration_input(email: str, username: str, password: str) -> Optional[str]:
    # Email validation using email_validator
    try:
        validate_email(email, check_deliverability=False)
    except EmailNotValidError:
        return "Email already in use or invalid data"
    # Username validation
    if not USERNAME_REGEX.match(username.strip()):
        return "Email already in use or invalid data"
    # Password basic validation (length)
    if not isinstance(password, str) or len(password) < 8:
        return "Email already in use or invalid data"
    return None

def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?", (email,))
    return cur.fetchone()

def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?", (username,))
    return cur.fetchone()

# -----------------------------
# Routes
# -----------------------------

@app.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"model": ErrorMessage, "description": "Bad Request"},
    },
)
def register(payload: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    # Input validation
    email = normalize_email(payload.email)
    username = payload.username.strip()
    password = payload.password

    invalid_msg = validate_registration_input(email, username, password)
    if invalid_msg:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=invalid_msg)

    # Secure password hashing using PBKDF2-SHA256
    password_hash = pbkdf2_sha256.hash(password)

    # Check uniqueness and insert user
    try:
        with db:
            # Enforce case-insensitive uniqueness for email by normalizing to lowercase.
            # Username is enforced unique as stored (case-sensitive). Adjust as needed.
            db.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, username, password_hash, datetime.now(timezone.utc).isoformat()),
            )
    except sqlite3.IntegrityError:
        # Likely a UNIQUE constraint violation for email or username
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")
    except sqlite3.Error:
        # Generic DB error (do not leak details)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

    return {"message": "Registration successful"}

@app.post(
    "/login",
    response_model=LoginResponse,
    responses={
        401: {"model": ErrorMessage, "description": "Unauthorized"},
    },
)
def login(payload: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    email = normalize_email(payload.email)
    password = payload.password

    try:
        user = get_user_by_email(db, email)
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

    if not user:
        # Do not reveal if the email exists (CWE-522/enum)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    # Verify password
    try:
        if not pbkdf2_sha256.verify(password, user["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    except (ValueError, TypeError):
        # Hash format error or similar
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    token = create_access_token(sub=user["username"], uid=user["id"], email=user["email"])
    return {"token": token, "message": "Login successful"}

@app.post(
    "/set_secret",
    response_model=SetSecretResponse,
    responses={
        401: {"model": ErrorMessage, "description": "Unauthorized"},
    },
)
def set_secret(payload: SetSecretRequest, claims: dict = Depends(get_current_claims), db: sqlite3.Connection = Depends(get_db)):
    # Authorization: token subject must match provided username
    provided_username = payload.username.strip()
    token_username = claims.get("sub")
    if not token_username or token_username != provided_username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    # Ensure the user exists
    try:
        user = get_user_by_username(db, provided_username)
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

    if not user:
        # Avoid user enumeration; treat as unauthorized
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    # Store or update the secret using parameterized query to avoid SQL injection (CWE-89)
    try:
        with db:
            db.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret = excluded.secret,
                    updated_at = excluded.updated_at
                """,
                (user["id"], payload.secret, datetime.now(timezone.utc).isoformat()),
            )
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

    return {"message": "Secret has been set successfully"}

@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
    responses={
        401: {"model": ErrorMessage, "description": "Unauthorized"},
    },
)
def get_secret(username: str = Query(..., example="user1"), claims: dict = Depends(get_current_claims), db: sqlite3.Connection = Depends(get_db)):
    requested_username = username.strip()
    token_username = claims.get("sub")
    if not token_username or token_username != requested_username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    try:
        user = get_user_by_username(db, requested_username)
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

    if not user:
        # Avoid user enumeration
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    try:
        cur = db.execute("SELECT secret FROM secrets WHERE user_id = ?", (user["id"],))
        row = cur.fetchone()
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

    secret_value = row["secret"] if row and row["secret"] is not None else ""
    return {"secret": secret_value}

# -----------------------------
# Run Server
# -----------------------------

if __name__ == "__main__":
    # Note: For production, run with a proper ASGI server and behind HTTPS termination.
    uvicorn.run(app, host="0.0.0.0", port=5000)