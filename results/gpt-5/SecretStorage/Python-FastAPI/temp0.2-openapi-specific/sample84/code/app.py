import os
import re
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, status, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, ValidationError
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn

# ----------------------------
# Configuration and Constants
# ----------------------------

DB_PATH = "db.sqlite3"
TOKEN_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # Token expiry for better security
APP_SECRET = os.environ.get("APP_SECRET") or os.environ.get("SECRET_KEY")

# If no APP_SECRET is provided, generate a strong random secret.
# Note: Tokens will be invalid across app restarts if using generated secret.
if not APP_SECRET:
    # Use os.urandom hex; no external pkg needed
    APP_SECRET = os.urandom(64).hex()

# Input constraints
MAX_EMAIL_LENGTH = 255
MAX_USERNAME_LENGTH = 50
MAX_PASSWORD_LENGTH = 1024
MAX_SECRET_LENGTH = 4096

USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_\-\.]{3,50}$")

# ----------------------------
# FastAPI app initialization
# ----------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


# ----------------------------
# Security Headers Middleware
# ----------------------------

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    try:
        response = await call_next(request)
    except Exception:
        # Generic exception safety - prevent stack traces leaking (CWE-703)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "Internal server error"},
        )
    # Add common security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


# ----------------------------
# Database Utilities
# ----------------------------

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Enforce foreign keys
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    conn = get_db_connection()
    try:
        # Set WAL for better concurrency
        conn.execute("PRAGMA journal_mode = WAL;")
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
    finally:
        conn.close()


@app.on_event("startup")
def startup_event():
    init_db()


# ----------------------------
# JWT Utilities
# ----------------------------

def create_access_token(username: str, email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=TOKEN_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[TOKEN_ALGORITHM])
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


# ----------------------------
# Dependencies
# ----------------------------

class CurrentUser:
    def __init__(self, id: int, username: str, email: str):
        self.id = id
        self.username = username
        self.email = email


async def get_current_user(request: Request) -> CurrentUser:
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = parts[1]
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
        user_row = conn.execute(
            "SELECT id, username, email FROM users WHERE username = ? AND email = ?",
            (username, email),
        ).fetchone()
    finally:
        conn.close()
    if not user_row:
        # Token valid but user not found (e.g., deleted)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return CurrentUser(id=user_row["id"], username=user_row["username"], email=user_row["email"])


# ----------------------------
# Pydantic Models
# ----------------------------

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., max_length=MAX_EMAIL_LENGTH, examples=["newuser@example.com"])
    username: str = Field(..., max_length=MAX_USERNAME_LENGTH, examples=["user1"])
    password: str = Field(..., min_length=8, max_length=MAX_PASSWORD_LENGTH, examples=["newUserPassword"])


class RegisterResponse(BaseModel):
    message: str = "Registration successful"


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., max_length=MAX_EMAIL_LENGTH, examples=["user@example.com"])
    password: str = Field(..., min_length=8, max_length=MAX_PASSWORD_LENGTH, examples=["mySecretPassword"])


class LoginResponse(BaseModel):
    token: str
    message: str = "Login successful"


class MessageResponse(BaseModel):
    message: str


class SetSecretRequest(BaseModel):
    username: str = Field(..., max_length=MAX_USERNAME_LENGTH, examples=["user1"])
    secret: str = Field(..., min_length=1, max_length=MAX_SECRET_LENGTH, examples=["mySecret"])


class GetSecretResponse(BaseModel):
    secret: str


# ----------------------------
# Helper Validation Functions
# ----------------------------

def validate_username(username: str) -> bool:
    if len(username) > MAX_USERNAME_LENGTH:
        return False
    return bool(USERNAME_REGEX.match(username))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ----------------------------
# Routes
# ----------------------------

@app.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register_user(body: RegisterRequest):
    # Validate username pattern
    if not validate_username(body.username):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )
    # Defensive checks for lengths
    if len(body.email) > MAX_EMAIL_LENGTH or len(body.password) > MAX_PASSWORD_LENGTH:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )

    email_lower = body.email.lower().strip()
    username = body.username.strip()

    # Hash password using a strong KDF (PBKDF2-SHA256)
    try:
        password_hash = pbkdf2_sha256.hash(body.password)
    except Exception:
        # Unexpected failure hashing password
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "Internal server error"},
        )

    conn = get_db_connection()
    try:
        # Check for existing email or username to avoid user enumeration details
        existing = conn.execute(
            "SELECT 1 FROM users WHERE email = ? OR username = ?",
            (email_lower, username),
        ).fetchone()
        if existing:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )

        now = now_iso()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (email_lower, username, password_hash, now, now),
        )
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Unique constraint failed or other integrity issue
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )
    except sqlite3.Error:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "Internal server error"},
        )
    finally:
        conn.close()


@app.post("/login", response_model=LoginResponse, status_code=status.HTTP_200_OK)
async def login_user(body: LoginRequest):
    # Basic defensive checks
    email_lower = body.email.lower().strip()
    if len(email_lower) > MAX_EMAIL_LENGTH or len(body.password) > MAX_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    conn = get_db_connection()
    try:
        user_row = conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (email_lower,),
        ).fetchone()
        if not user_row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )
        # Verify password using constant-time check from passlib
        if not pbkdf2_sha256.verify(body.password, user_row["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )
        token = create_access_token(username=user_row["username"], email=user_row["email"])
        return {"token": token, "message": "Login successful"}
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )
    finally:
        conn.close()


@app.post("/set_secret", response_model=MessageResponse, status_code=status.HTTP_200_OK)
async def set_secret(body: SetSecretRequest, current_user: CurrentUser = Depends(get_current_user)):
    # Authorization: ensure token subject matches provided username (CWE-284/CWE-863)
    if current_user.username != body.username.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if len(body.secret) > MAX_SECRET_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid data",
        )

    conn = get_db_connection()
    try:
        # Ensure the user exists (should be true given dependency), and upsert secret
        now = now_iso()
        # Check if secret exists for user
        existing = conn.execute(
            "SELECT id FROM secrets WHERE user_id = ?",
            (current_user.id,),
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
                (body.secret, now, current_user.id),
            )
        else:
            conn.execute(
                "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
                (current_user.id, body.secret, now),
            )
        return {"message": "Secret has been set successfully"}
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )
    finally:
        conn.close()


@app.get("/get_secret", response_model=GetSecretResponse, status_code=status.HTTP_200_OK)
async def get_secret(username: str, current_user: CurrentUser = Depends(get_current_user)):
    # Authorization: token user must match requested username (CWE-284/CWE-863)
    if current_user.username != username.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT secret FROM secrets WHERE user_id = ?",
            (current_user.id,),
        ).fetchone()
        secret_value = row["secret"] if row else ""
        return {"secret": secret_value}
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )
    finally:
        conn.close()


# ----------------------------
# Global Exception Handlers
# ----------------------------

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Standardize error responses to match schema where possible
    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
        return JSONResponse(
            status_code=exc.status_code,
            content={"message": str(exc.detail)},
            headers=exc.headers or {},
        )
    elif exc.status_code == status.HTTP_400_BAD_REQUEST:
        return JSONResponse(
            status_code=exc.status_code,
            content={"message": "Email already in use or invalid data" if "invalid" in str(exc.detail).lower() else str(exc.detail)},
        )
    elif exc.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR:
        return JSONResponse(
            status_code=exc.status_code,
            content={"message": "Internal server error"},
        )
    else:
        # Default
        return JSONResponse(
            status_code=exc.status_code,
            content={"message": str(exc.detail)},
        )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Catch-all to avoid leaking internals (CWE-703)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "Internal server error"},
    )


# ----------------------------
# Entrypoint
# ----------------------------

if __name__ == "__main__":
    # Ensure DB initialized before starting the server
    try:
        init_db()
    except Exception:
        # If initialization fails, exit gracefully
        raise SystemExit("Failed to initialize database.")
    uvicorn.run(app, host="0.0.0.0", port=5000)