import os
import re
import sqlite3
import sys
import logging
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import uvicorn
from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.exceptions import RequestValidationError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.status import HTTP_200_OK, HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_500_INTERNAL_SERVER_ERROR
from pydantic import BaseModel, EmailStr, Field, validator
import jwt  # pyjwt
from passlib.hash import pbkdf2_sha256

# ------------------------------------------------------------------------------
# Configuration & Logging
# ------------------------------------------------------------------------------

APP_NAME = "Secret Storage"
DB_PATH = "db.sqlite3"

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(APP_NAME)

# Secret key for JWT
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fall back to a strong random secret if not provided.
    # Note: Tokens will be invalidated on restart if not using a persistent secret.
    APP_SECRET = pysecrets.token_urlsafe(64)
    logger.warning("APP_SECRET environment variable not set. Using a temporary in-memory secret. Tokens will be invalidated on restart.")

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# A dummy password hash to mitigate user enumeration/timing attacks during login
DUMMY_PASSWORD_HASH = pbkdf2_sha256.hash("this_is_a_dummy_password_value_for_timing")


# ------------------------------------------------------------------------------
# Database Utilities
# ------------------------------------------------------------------------------

def get_db_connection() -> sqlite3.Connection:
    """
    Create and return a new sqlite3 connection with sane defaults and safety.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Enable foreign keys and set WAL for better concurrency
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.DatabaseError:
        # Ignore if not supported in this environment
        pass
    return conn


def init_db() -> None:
    """
    Initialize the SQLite database with required tables.
    """
    try:
        conn = get_db_connection()
        with conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at DATETIME NOT NULL DEFAULT (CURRENT_TIMESTAMP),
                    updated_at DATETIME NOT NULL DEFAULT (CURRENT_TIMESTAMP)
                );

                CREATE TABLE IF NOT EXISTS secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT NOT NULL,
                    created_at DATETIME NOT NULL DEFAULT (CURRENT_TIMESTAMP),
                    updated_at DATETIME NOT NULL DEFAULT (CURRENT_TIMESTAMP),
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
        conn.close()
    except Exception as e:
        logger.exception("Database initialization failed: %s", e)
        raise


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


# ------------------------------------------------------------------------------
# Security & Auth Helpers
# ------------------------------------------------------------------------------

def create_access_token(*, user_id: int, username: str, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta if expires_delta is not None else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {
        "sub": str(user_id),
        "uid": user_id,
        "username": username,
        "iat": now,
        "exp": expire,
        "jti": pysecrets.token_urlsafe(16),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# ------------------------------------------------------------------------------
# Pydantic Models
# ------------------------------------------------------------------------------

USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., description="User email")
    username: str = Field(..., min_length=3, max_length=32, description="Username")
    password: str = Field(..., min_length=8, max_length=128, description="Password")

    @validator("username")
    def validate_username(cls, v: str) -> str:
        if not USERNAME_REGEX.match(v):
            raise ValueError("Username must be 3-32 chars and contain only letters, numbers, '_', '.', or '-'")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=128)


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    secret: str = Field(..., min_length=1, max_length=4096)

    @validator("username")
    def validate_username(cls, v: str) -> str:
        if not USERNAME_REGEX.match(v):
            raise ValueError("Invalid username format")
        return v


# ------------------------------------------------------------------------------
# FastAPI App Initialization
# ------------------------------------------------------------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Security Middleware to set secure headers
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        return response

app.add_middleware(SecurityHeadersMiddleware)

# Optional: Restrictive CORS (adjust as needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[],  # specify origins explicitly in production
    allow_credentials=True,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# Initialize the database at startup
@app.on_event("startup")
def startup_event():
    init_db()
    logger.info("Database initialized and application started.")


# ------------------------------------------------------------------------------
# Exception Handlers (CWE-703: robust error handling)
# ------------------------------------------------------------------------------

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Return a 400 Bad Request with a general message to avoid leaking too much detail
    return JSONResponse(
        status_code=HTTP_400_BAD_REQUEST,
        content={"message": "Email already in use or invalid data"} if request.url.path == "/register" else {"message": "Invalid request parameters"},
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error processing request %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "An unexpected error occurred"},
    )


# ------------------------------------------------------------------------------
# Authentication Dependency
# ------------------------------------------------------------------------------

bearer_scheme = HTTPBearer(auto_error=False)

async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)) -> Optional[sqlite3.Row]:
    """
    Validates the bearer token and returns the associated user row.
    Returns None if invalid.
    """
    if credentials is None or credentials.scheme.lower() != "bearer":
        return None
    token = credentials.credentials
    payload = decode_token(token)
    if not payload:
        return None
    uid = payload.get("uid")
    username = payload.get("username")
    if uid is None or username is None:
        return None
    user = get_user_by_id(int(uid))
    if not user:
        return None
    # Ensure token username matches current username in DB (prevents stale tokens if username ever changed)
    if user["username"] != username:
        return None
    return user


# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@app.post("/register", status_code=HTTP_201_CREATED, include_in_schema=True)
def register(payload: RegisterRequest):
    """
    Register a new user with email, username, and password.
    """
    try:
        # Basic checks for existing email/username to give a clean 400
        existing_by_email = get_user_by_email(payload.email)
        if existing_by_email:
            return JSONResponse(
                status_code=HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )

        existing_by_username = get_user_by_username(payload.username)
        if existing_by_username:
            return JSONResponse(
                status_code=HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )

        password_hash = pbkdf2_sha256.hash(payload.password)

        conn = get_db_connection()
        try:
            with conn:
                conn.execute(
                    "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
                    (payload.email.strip().lower(), payload.username.strip(), password_hash),
                )
        finally:
            conn.close()

        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Catch any unique constraint violations (defense-in-depth)
        return JSONResponse(
            status_code=HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )
    except Exception as e:
        logger.exception("Registration failed: %s", e)
        return JSONResponse(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "An unexpected error occurred"},
        )


@app.post("/login", status_code=HTTP_200_OK, include_in_schema=True)
def login(payload: LoginRequest):
    """
    Authenticate a user with email and password and return a JWT token.
    """
    try:
        user = get_user_by_email(payload.email.strip().lower())
        if not user:
            # Mitigate timing attacks by verifying against a dummy hash
            try:
                pbkdf2_sha256.verify(payload.password, DUMMY_PASSWORD_HASH)
            except Exception:
                pass
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
            )

        # Verify password
        is_valid = False
        try:
            is_valid = pbkdf2_sha256.verify(payload.password, user["password_hash"])
        except Exception:
            # If verification fails due to any reason, treat as invalid
            is_valid = False

        if not is_valid:
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
            )

        token = create_access_token(user_id=int(user["id"]), username=user["username"])
        return {"token": token, "message": "Login successful"}
    except Exception as e:
        logger.exception("Login failed: %s", e)
        return JSONResponse(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "An unexpected error occurred"},
        )


@app.post("/set_secret", status_code=HTTP_200_OK, include_in_schema=True)
def set_secret(payload: SetSecretRequest, current_user: Optional[sqlite3.Row] = Depends(get_current_user)):
    """
    Save a secret on the server using the username, token, and the secret text.
    Requires a valid Bearer token. User can only set their own secret.
    """
    try:
        # Authentication and Authorization enforcement (CWE-284, CWE-863)
        if current_user is None:
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid authentication token"},
            )
        if current_user["username"] != payload.username:
            # Prevent IDOR - token user must match payload username
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid authentication token"},
            )

        user_id = int(current_user["id"])

        conn = get_db_connection()
        try:
            with conn:
                # Upsert secret securely (CWE-89: parameterized queries)
                conn.execute(
                    """
                    INSERT INTO secrets (user_id, secret) VALUES (?, ?)
                    ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=CURRENT_TIMESTAMP
                    """,
                    (user_id, payload.secret),
                )
        finally:
            conn.close()

        return {"message": "Secret has been set successfully"}
    except Exception as e:
        logger.exception("Set secret failed: %s", e)
        return JSONResponse(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "An unexpected error occurred"},
        )


@app.get("/get_secret", status_code=HTTP_200_OK, include_in_schema=True)
def get_secret(username: str, current_user: Optional[sqlite3.Row] = Depends(get_current_user)):
    """
    Retrieve a secret based on the provided username.
    Requires a valid Bearer token. User can only get their own secret.
    """
    try:
        # Basic username validation to keep consistent restrictions
        if not USERNAME_REGEX.match(username):
            # Treat as unauthorized to avoid leaking existence information
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid authentication token"},
            )

        # Authentication and Authorization enforcement
        if current_user is None:
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid authentication token"},
            )

        if current_user["username"] != username:
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid authentication token"},
            )

        conn = get_db_connection()
        try:
            cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (int(current_user["id"]),))
            row = cur.fetchone()
        finally:
            conn.close()

        secret_value = row["secret"] if row else ""
        return {"secret": secret_value}
    except Exception as e:
        logger.exception("Get secret failed: %s", e)
        return JSONResponse(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "An unexpected error occurred"},
        )


# ------------------------------------------------------------------------------
# Run the application
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    # Start Uvicorn server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)