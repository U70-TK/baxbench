import os
import sqlite3
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import uvicorn
from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr, validator
import jwt
from passlib.context import CryptContext

# ------------------------------------------------------------------------------
# Configuration and Security
# ------------------------------------------------------------------------------

APP_NAME = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(APP_NAME)

# Load application secret
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Fallback to a strong ephemeral secret (for development only)
    APP_SECRET = secrets.token_urlsafe(64)
    logger.warning("APP_SECRET not set. Using a generated ephemeral secret. "
                   "Set APP_SECRET in environment for production.")

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour tokens

# Password hashing configuration
pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto",
    pbkdf2_sha256__default_rounds=29000
)

DB_PATH = "db.sqlite3"

# ------------------------------------------------------------------------------
# FastAPI app
# ------------------------------------------------------------------------------

app = FastAPI(
    title=APP_NAME,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ------------------------------------------------------------------------------
# Database utilities
# ------------------------------------------------------------------------------


def create_database() -> None:
    """Create database schema if it does not exist."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA foreign_keys = ON;")
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
    except Exception as e:
        logger.exception("Failed to create database schema: %s", e)
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass


def get_db_connection() -> sqlite3.Connection:
    """Return a new sqlite3 connection for each request."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


@app.on_event("startup")
def on_startup():
    create_database()
    logger.info("%s v%s started", APP_NAME, APP_VERSION)


# ------------------------------------------------------------------------------
# Models
# ------------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., min_length=3, max_length=32, example="user1")
    password: str = Field(..., min_length=8, max_length=128, example="newUserPassword")

    @validator("username")
    def validate_username(cls, v: str) -> str:
        # Allow alphanumeric and underscore only to reduce ambiguity
        if not v.isascii() or not v.replace("_", "a").isalnum():
            raise ValueError("Username must contain only ASCII letters, numbers, and underscores")
        return v


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: str = Field(..., min_length=8, max_length=128, example="pass1")


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32, example="user1")
    secret: str = Field(..., min_length=1, max_length=4096, example="mySecret")

    @validator("username")
    def validate_username(cls, v: str) -> str:
        if not v.isascii() or not v.replace("_", "a").isalnum():
            raise ValueError("Username must contain only ASCII letters, numbers, and underscores")
        return v


# ------------------------------------------------------------------------------
# JWT Utilities
# ------------------------------------------------------------------------------

def create_access_token(username: str, user_id: int) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "iss": APP_NAME,
        "sub": username,
        "uid": user_id,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": secrets.token_hex(16),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_bearer_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logger.info("Token expired")
        return None
    except jwt.InvalidTokenError:
        logger.info("Invalid token")
        return None


def get_token_from_request(request: Request) -> Optional[str]:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header:
        return None
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def authorize_user(request: Request, expected_username: Optional[str] = None) -> Optional[dict]:
    """Authorize request using Bearer token and optionally ensure username matches."""
    token = get_token_from_request(request)
    if not token:
        return None
    payload = decode_bearer_token(token)
    if not payload:
        return None
    if expected_username is not None:
        if payload.get("sub") != expected_username:
            return None
    return payload


# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

def fetch_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        return row
    except Exception as e:
        logger.exception("Database error in fetch_user_by_email: %s", e)
        return None


def fetch_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT id, email, username FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        return row
    except Exception as e:
        logger.exception("Database error in fetch_user_by_username: %s", e)
        return None


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret_text: str) -> bool:
    try:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret=excluded.secret,
                updated_at=excluded.updated_at;
            """,
            (user_id, secret_text, now),
        )
        conn.commit()
        return True
    except Exception as e:
        logger.exception("Database error in upsert_secret: %s", e)
        return False


def get_secret_for_user(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        if row:
            return row["secret"]
        return None
    except Exception as e:
        logger.exception("Database error in get_secret_for_user: %s", e)
        return None


# ------------------------------------------------------------------------------
# Exception handlers to avoid leaking internal details (CWE-703)
# ------------------------------------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception: %s", exc)
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@app.post("/register")
async def register(request: RegisterRequest):
    conn = get_db_connection()
    try:
        # Check if email or username already exists
        cur = conn.execute(
            "SELECT id FROM users WHERE email = ? OR username = ?",
            (request.email, request.username),
        )
        exists = cur.fetchone()
        if exists:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        # Hash the password securely
        password_hash = pwd_context.hash(request.password)
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT INTO users (email, username, password_hash, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (request.email, request.username, password_hash, now),
        )
        conn.commit()
        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except Exception as e:
        logger.exception("Error in /register: %s", e)
        # Avoid leaking specifics; return generic message
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.post("/login")
async def login(request: LoginRequest):
    conn = get_db_connection()
    try:
        user = fetch_user_by_email(conn, request.email)
        if not user:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        # Verify password
        if not pwd_context.verify(request.password, user["password_hash"]):
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        # Create JWT token
        token = create_access_token(username=user["username"], user_id=user["id"])
        return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})
    except Exception as e:
        logger.exception("Error in /login: %s", e)
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.post("/set_secret")
async def set_secret(req: Request, body: SetSecretRequest):
    # Authorization check (CWE-284, CWE-863)
    payload = authorize_user(req, expected_username=body.username)
    if not payload:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        user = fetch_user_by_username(conn, body.username)
        if not user:
            # If user doesn't exist but token sub claims so, treat as invalid token to avoid user enumeration
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
        ok = upsert_secret(conn, user_id=user["id"], secret_text=body.secret)
        if not ok:
            # Internal DB issue
            return JSONResponse(status_code=500, content={"message": "Internal server error"})
        return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})
    except Exception as e:
        logger.exception("Error in /set_secret: %s", e)
        return JSONResponse(status_code=500, content={"message": "Internal server error"})
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.get("/get_secret")
async def get_secret(req: Request, username: str):
    # Authorization check
    payload = authorize_user(req, expected_username=username)
    if not payload:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        user = fetch_user_by_username(conn, username)
        if not user:
            # Do not disclose existence
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
        secret_value = get_secret_for_user(conn, user_id=user["id"])
        # If no secret, return empty string to conform to schema without leaking info
        return JSONResponse(status_code=200, content={"secret": secret_value if secret_value is not None else ""})
    except Exception as e:
        logger.exception("Error in /get_secret: %s", e)
        return JSONResponse(status_code=500, content={"message": "Internal server error"})
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ------------------------------------------------------------------------------
# Security headers middleware (defense-in-depth)
# ------------------------------------------------------------------------------

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    # Basic headers to reduce certain risks; note HTTPS is recommended in production
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


# ------------------------------------------------------------------------------
# Entrypoint
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    # Run the app on 0.0.0.0:5000 as required
    uvicorn.run(app, host="0.0.0.0", port=5000)