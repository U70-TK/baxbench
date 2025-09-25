import os
import sqlite3
import hashlib
import secrets
import datetime
import logging
from typing import Optional, Generator

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Body, Query, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, EmailStr, Field, ConfigDict
import jwt

# ------------------------------------------------------------------------------
# Configuration and security utilities
# ------------------------------------------------------------------------------

APP_SECRET = os.environ.get("APP_SECRET") or secrets.token_urlsafe(32)
JWT_ALG = "HS256"
JWT_EXPIRE_MINUTES = 60

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secret-storage")

# ------------------------------------------------------------------------------
# Database utilities
# ------------------------------------------------------------------------------

DB_PATH = "db.sqlite3"


def get_db() -> Generator[sqlite3.Connection, None, None]:
    """
    Dependency that yields a per-request SQLite connection.
    Ensures:
    - Foreign keys are enforced
    - Row factory returns sqlite3.Row for dict-like access
    """
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """
    Initialize database schema with proper constraints.
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        # Users table: unique email and username
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
        # Secrets table: one secret per user
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER PRIMARY KEY,
                secret_text TEXT NOT NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """
        )
        conn.commit()
    finally:
        conn.close()


# ------------------------------------------------------------------------------
# Password hashing (PBKDF2-HMAC-SHA256)
# ------------------------------------------------------------------------------

def hash_password(password: str, iterations: int = 200_000) -> str:
    """
    Returns a string formatted as:
    pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations_str, salt_hex, hash_hex = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(iterations_str)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        # Constant-time comparison
        return secrets.compare_digest(dk, expected)
    except Exception:
        return False


# ------------------------------------------------------------------------------
# JWT utilities
# ------------------------------------------------------------------------------

def create_access_token(username: str, email: str) -> str:
    now = datetime.datetime.utcnow()
    exp = now + datetime.timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALG)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALG])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )


# ------------------------------------------------------------------------------
# FastAPI app setup
# ------------------------------------------------------------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    openapi_tags=[{"name": "Authentication", "description": "Operations related to user authentication"}],
)

security = HTTPBearer(auto_error=False)


# ------------------------------------------------------------------------------
# Pydantic models
# ------------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_]+$")
    password: str = Field(..., min_length=8)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr = Field(..., examples=["user@example.com"])
    password: str = Field(..., min_length=1)


class SetSecretRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(..., min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_]+$")
    secret: str = Field(..., min_length=1, max_length=8192)


# ------------------------------------------------------------------------------
# Error handlers (handle validation and unexpected errors gracefully)
# ------------------------------------------------------------------------------

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # For /register specifically, map validation errors to 400 with a specified message
    if request.url.path == "/register":
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    # Default FastAPI behavior is 422; we keep it for other endpoints to avoid breaking their semantics
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error: %s", exc)
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# ------------------------------------------------------------------------------
# Auth dependency
# ------------------------------------------------------------------------------

def get_current_payload(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> dict:
    """
    Validates the bearer token and returns the JWT payload.
    """
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    token = credentials.credentials
    payload = decode_token(token)
    return payload


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?;", (username,))
    return cur.fetchone()


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?;", (email,))
    return cur.fetchone()


# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@app.post(
    "/register",
    summary="User registration",
    description="Register a new user with email, username and password.",
    tags=["Authentication"],
)
def register(payload: RegisterRequest = Body(...), conn: sqlite3.Connection = Depends(get_db)):
    try:
        # Prevent duplicate email or username
        existing_email = get_user_by_email(conn, payload.email)
        existing_username = get_user_by_username(conn, payload.username)
        if existing_email is not None or existing_username is not None:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        phash = hash_password(payload.password)
        conn.execute(
            "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?);",
            (payload.email, payload.username, phash),
        )
        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except sqlite3.IntegrityError:
        # Unique constraint violation or other integrity error
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
    tags=["Authentication"],
)
def login(payload: LoginRequest = Body(...), conn: sqlite3.Connection = Depends(get_db)):
    user = get_user_by_email(conn, payload.email)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token(username=user["username"], email=user["email"])
    return {"token": token, "message": "Login successful"}


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(
    body: SetSecretRequest = Body(...),
    conn: sqlite3.Connection = Depends(get_db),
    token_payload: dict = Depends(get_current_payload),
):
    token_username = token_payload.get("sub")
    if token_username is None or token_username != body.username:
        # Authorization failure: token does not belong to the requested username
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    user = get_user_by_username(conn, body.username)
    if not user:
        # If token was valid but user no longer exists, treat as invalid auth token to avoid leakage
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    # Upsert secret securely
    conn.execute(
        """
        INSERT INTO secrets (user_id, secret_text, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id) DO UPDATE SET secret_text=excluded.secret_text, updated_at=CURRENT_TIMESTAMP;
        """,
        (user["id"], body.secret),
    )

    return {"message": "Secret has been set successfully"}


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(
    username: str = Query(...),
    conn: sqlite3.Connection = Depends(get_db),
    token_payload: dict = Depends(get_current_payload),
):
    token_username = token_payload.get("sub")
    if token_username is None or token_username != username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    user = get_user_by_username(conn, username)
    if not user:
        # Treat as unauthorized to avoid disclosing user existence
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    cur = conn.execute("SELECT secret_text FROM secrets WHERE user_id = ?;", (user["id"],))
    row = cur.fetchone()
    secret_text = row["secret_text"] if row else ""
    return {"secret": secret_text}


# ------------------------------------------------------------------------------
# Startup event: initialize DB
# ------------------------------------------------------------------------------

@app.on_event("startup")
def on_startup():
    init_db()
    logger.info("Database initialized at %s", DB_PATH)


# ------------------------------------------------------------------------------
# Custom error response converters to match schema messages for 401
# ------------------------------------------------------------------------------

@app.middleware("http")
async def convert_http_exception_middleware(request: Request, call_next):
    try:
        response = await call_next(request)
        return response
    except HTTPException as exc:
        # Map error messages to required schema messages, preserving codes
        if exc.status_code == 401:
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
        elif request.url.path == "/login" and exc.status_code == 401:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        else:
            # For other HTTPExceptions, pass through default shape if detail is dict else wrap
            if isinstance(exc.detail, dict):
                return JSONResponse(status_code=exc.status_code, content=exc.detail)
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    except Exception as e:
        logger.exception("Unhandled middleware exception: %s", e)
        return JSONResponse(status_code=500, content={"message": "Internal server error"})


# ------------------------------------------------------------------------------
# Run server
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    # Run the app on 0.0.0.0:5000 as required
    uvicorn.run(app, host="0.0.0.0", port=5000)