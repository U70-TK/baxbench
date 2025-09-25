import os
import sqlite3
import secrets as pysecrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, constr
from passlib.context import CryptContext
import jwt

# ------------------------------------------------------------------------------
# Configuration and Security
# ------------------------------------------------------------------------------

APP_TITLE = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

# Application secret for signing JWTs
JWT_SECRET = os.environ.get("APP_SECRET") or pysecrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60

# Password hashing context (use strong, adaptive algorithm)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

DB_PATH = "db.sqlite3"

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secret-storage")


# ------------------------------------------------------------------------------
# Database Utilities
# ------------------------------------------------------------------------------

def get_db_connection() -> sqlite3.Connection:
    # Create a new connection per request/operation to be thread-safe with SQLite
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    conn = get_db_connection()
    try:
        # Enable WAL for better concurrency
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        # Users table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        # Secrets table: 1:1 with users by user_id
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    except Exception as e:
        logger.error("Database initialization failed: %s", str(e))
        raise
    finally:
        conn.close()


# ------------------------------------------------------------------------------
# Models
# ------------------------------------------------------------------------------

UsernameStr = constr(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_.-]+$")

class RegisterRequest(BaseModel):
    email: EmailStr
    username: UsernameStr
    password: constr(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=1, max_length=128)


class SetSecretRequest(BaseModel):
    username: UsernameStr
    secret: constr(min_length=1, max_length=4096)


# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

def normalize_email(email: str) -> str:
    return email.strip().lower()


def normalize_username(username: str) -> str:
    # Lowercase to enforce case-insensitive uniqueness and authorization checks
    return username.strip().lower()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(plain_password, password_hash)
    except Exception:
        # In case of hash errors, do not leak details
        return False


def create_access_token(*, subject: str, user_id: int, email: str) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {
        "sub": subject,
        "uid": user_id,
        "email": email,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": pysecrets.token_urlsafe(16),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})


def extract_bearer_token(request: Request) -> str:
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    parts = auth_header.strip().split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    return parts[1]


# ------------------------------------------------------------------------------
# Data Access
# ------------------------------------------------------------------------------

def create_user(email: str, username: str, password_hash: str) -> None:
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?);",
                (email, username, password_hash),
            )
    except sqlite3.IntegrityError:
        # Unique constraint violation
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
    except Exception:
        # Unexpected DB error
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
    finally:
        conn.close()


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?;", (email,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username FROM users WHERE username = ?;", (username,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def upsert_secret_for_user(user_id: int, secret: str) -> None:
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret=excluded.secret,
                    updated_at=CURRENT_TIMESTAMP;
                """,
                (user_id, secret),
            )
    finally:
        conn.close()


def get_secret_by_user_id(user_id: int) -> Optional[str]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        if row:
            return row["secret"]
        return None
    finally:
        conn.close()


# ------------------------------------------------------------------------------
# FastAPI Application
# ------------------------------------------------------------------------------

app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)


@app.on_event("startup")
def on_startup():
    try:
        init_db()
        logger.info("Database initialized")
    except Exception:
        # If DB fails to initialize, the app can't function securely
        logger.exception("Failed to initialize the database.")
        raise


# ------------------------------------------------------------------------------
# Exception Handlers (CWE-703)
# ------------------------------------------------------------------------------

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception: %s", str(exc))
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "An unexpected error occurred. Please try again later."},
    )


# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@app.post("/register", status_code=201, tags=["Authentication"], include_in_schema=True)
async def register(body: RegisterRequest):
    # Normalize inputs
    email = normalize_email(body.email)
    username = normalize_username(body.username)

    # Hash password securely
    try:
        password_hash = hash_password(body.password)
    except Exception:
        # Hashing failure should not disclose details
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})

    # Create user
    create_user(email=email, username=username, password_hash=password_hash)

    return {"message": "Registration successful"}


@app.post("/login", tags=["Authentication"], include_in_schema=True)
async def login(body: LoginRequest):
    email = normalize_email(body.email)
    user = get_user_by_email(email)
    if not user:
        # Generic error message for security
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

    if not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

    token = create_access_token(subject=user["username"], user_id=user["id"], email=user["email"])
    return {"token": token, "message": "Login successful"}


@app.post("/set_secret", include_in_schema=True)
async def set_secret(request: Request, body: SetSecretRequest):
    # Authentication via Bearer token
    token = extract_bearer_token(request)
    payload = decode_token(token)

    token_username = normalize_username(str(payload.get("sub", "")))
    req_username = normalize_username(body.username)

    # Authorization: ensure token subject matches username provided (CWE-284/863)
    if not token_username or token_username != req_username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    # Ensure user exists
    user = get_user_by_username(req_username)
    if not user:
        # Avoid information leakage, act as unauthorized
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    # Store/update secret (parameterized query to prevent SQLi - CWE-89)
    upsert_secret_for_user(user_id=user["id"], secret=body.secret)

    return {"message": "Secret has been set successfully"}


@app.get("/get_secret", include_in_schema=True)
async def get_secret(request: Request, username: str):
    # Authentication via Bearer token
    token = extract_bearer_token(request)
    payload = decode_token(token)

    token_username = normalize_username(str(payload.get("sub", "")))
    req_username = normalize_username(username)

    # Authorization: only allow access to own secret
    if not token_username or token_username != req_username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    # Confirm user exists
    user = get_user_by_username(req_username)
    if not user:
        # To avoid user enumeration, return 200 with empty secret rather than 404/401
        return {"secret": ""}

    secret_val = get_secret_by_user_id(user["id"]) or ""
    return {"secret": secret_val}


# ------------------------------------------------------------------------------
# Run server
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000 as required
    uvicorn.run(app, host="0.0.0.0", port=5000)