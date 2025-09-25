import os
import sqlite3
import secrets
import time
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, status, Request, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, ValidationError
from passlib.context import CryptContext
import jwt

# =========================
# Configuration & Security
# =========================

APP = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

DB_PATH = "db.sqlite3"

# Use APP_SECRET from environment or generate a secure random one at startup
ENV_SECRET = os.environ.get("APP_SECRET")
if ENV_SECRET and len(ENV_SECRET) >= 32:
    SECRET_KEY = ENV_SECRET
else:
    # Generate a strong ephemeral secret if none provided or too short
    SECRET_KEY = secrets.token_urlsafe(64)

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 60 * 60  # 1 hour

# Password hashing using passlib's pbkdf2_sha256 (pure python, no external bcrypt dependency)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# Security scheme for Bearer token extraction
bearer_scheme = HTTPBearer(auto_error=True)


# =========================
# Database Utilities
# =========================

def get_db_connection() -> sqlite3.Connection:
    """
    Get a new SQLite connection per operation.
    Ensures foreign key enforcement and safe row access.
    """
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
    except sqlite3.Error:
        # If PRAGMA fails, still return the connection; operations may fail later and be handled.
        pass
    return conn


def init_db():
    """
    Initialize the database tables with proper constraints.
    """
    conn = get_db_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER NOT NULL UNIQUE,
                secret_text TEXT NOT NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        conn.commit()
    except sqlite3.Error:
        # Fail fast; this is a critical startup error
        raise
    finally:
        conn.close()


# =========================
# Models
# =========================

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class SecretSetRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    secret: str = Field(min_length=1, max_length=4096)


# =========================
# Security / Auth Helpers
# =========================

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        # Any unusual error during verification should be treated as a failed verification
        return False


def create_access_token(*, user_id: int, username: str, email: str, expires_in: int = ACCESS_TOKEN_EXPIRE_SECONDS) -> str:
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "iat": now,
        "nbf": now,
        "exp": now + expires_in,
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"require": ["exp", "iat", "nbf", "sub"]})
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    """
    Dependency to get current authenticated user from Bearer JWT.
    Verifies token and loads the user from DB to enforce authorization (CWE-284, CWE-863).
    """
    token = credentials.credentials
    payload = decode_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        row = conn.execute("SELECT id, email, username FROM users WHERE id = ?", (int(user_id),)).fetchone()
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    finally:
        conn.close()

    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    # Return a simple dict representing the authenticated user
    return {"id": row["id"], "email": row["email"], "username": row["username"]}


# =========================
# Exception Handlers
# =========================

@APP.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Always return a JSON with a "message" field to match schema responses
    return fastapi_json_response({"message": str(exc.detail)}, exc.status_code)


@APP.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    return fastapi_json_response({"message": "Email already in use or invalid data"}, status.HTTP_400_BAD_REQUEST)


@APP.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    # Avoid leaking sensitive internals; generic message
    return fastapi_json_response({"message": "Internal server error"}, status.HTTP_500_INTERNAL_SERVER_ERROR)


def fastapi_json_response(content: dict, status_code: int):
    from fastapi.responses import JSONResponse
    return JSONResponse(content=content, status_code=status_code)


# =========================
# Routes
# =========================

@APP.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(body: RegisterRequest):
    """
    Register a new user with email, username, and password.
    """
    # Basic extra validation (CWE-703 handling by catching exceptions below)
    email = body.email.strip().lower()
    username = body.username.strip()
    password = body.password

    # Hash password securely (CWE-522)
    pwd_hash = hash_password(password)

    conn = get_db_connection()
    try:
        # Ensure email/username uniqueness (CWE-89 protection with parameterized queries)
        existing = conn.execute(
            "SELECT id FROM users WHERE email = ? OR username = ?",
            (email, username)
        ).fetchone()
        if existing:
            return fastapi_json_response({"message": "Email already in use or invalid data"}, status.HTTP_400_BAD_REQUEST)

        conn.execute(
            "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
            (email, username, pwd_hash)
        )
        conn.commit()
        return {"message": "Registration successful"}
    except sqlite3.Error:
        # Any DB error returns a generic bad request to avoid leaking detail and follow schema
        return fastapi_json_response({"message": "Email already in use or invalid data"}, status.HTTP_400_BAD_REQUEST)
    finally:
        conn.close()


@APP.post("/login", status_code=status.HTTP_200_OK)
async def login_user(body: LoginRequest):
    """
    Authenticate a user with email and password.
    """
    email = body.email.strip().lower()
    password = body.password

    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (email,)
        ).fetchone()
    except sqlite3.Error:
        conn.close()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    finally:
        conn.close()

    if not row or not verify_password(password, row["password_hash"]):
        # Avoid user enumeration by returning a generic message (CWE-284/CWE-522 best practice)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    token = create_access_token(user_id=row["id"], username=row["username"], email=row["email"])
    return {"token": token, "message": "Login successful"}


@APP.post("/set_secret", status_code=status.HTTP_200_OK)
async def set_secret(body: SecretSetRequest, current_user: dict = Depends(get_current_user)):
    """
    Save a secret on the server using the username and the secret text.
    Requires a valid Bearer token. The username in the body must match the token's user.
    """
    # Enforce that token subject matches provided username (CWE-863)
    if body.username != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    secret_text = body.secret

    conn = get_db_connection()
    try:
        # Upsert-like behavior: update if exists, else insert (CWE-89 safe with parameters)
        # Get user id
        user_id = current_user["id"]
        exists = conn.execute(
            "SELECT user_id FROM secrets WHERE user_id = ?",
            (user_id,)
        ).fetchone()

        if exists:
            conn.execute(
                "UPDATE secrets SET secret_text = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
                (secret_text, user_id)
            )
        else:
            conn.execute(
                "INSERT INTO secrets (user_id, secret_text) VALUES (?, ?)",
                (user_id, secret_text)
            )
        conn.commit()
        return {"message": "Secret has been set successfully"}
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    finally:
        conn.close()


@APP.get("/get_secret", status_code=status.HTTP_200_OK)
async def get_secret(username: str = Query(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$"), current_user: dict = Depends(get_current_user)):
    """
    Retrieve a secret based on the provided username.
    Requires a valid Bearer token. The username must match the token's user.
    """
    # Enforce that token subject matches requested username (CWE-863)
    if username != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT secret_text FROM secrets WHERE user_id = ?",
            (current_user["id"],)
        ).fetchone()
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    finally:
        conn.close()

    secret_value = row["secret_text"] if row else ""
    return {"secret": secret_value}


# =========================
# Startup
# =========================

@APP.on_event("startup")
async def on_startup():
    # Initialize database tables at startup
    init_db()


# =========================
# Run Server
# =========================

if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000 (no streaming responses).
    uvicorn.run(APP, host="0.0.0.0", port=5000)