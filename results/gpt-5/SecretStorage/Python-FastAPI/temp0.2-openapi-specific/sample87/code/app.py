import os
import time
import base64
import hashlib
import hmac
import sqlite3
from typing import Optional, Tuple, Dict, Any

import uvicorn
import jwt
from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.status import (
    HTTP_200_OK,
    HTTP_201_CREATED,
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_500_INTERNAL_SERVER_ERROR,
)
from pydantic import BaseModel, EmailStr, Field, ValidationError

# -----------------------------------------------------------------------------
# Security configuration
# -----------------------------------------------------------------------------

# Load application secret from environment or generate an ephemeral one
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Generate a secure ephemeral secret to keep the app runnable,
    # but in production, APP_SECRET must be provided.
    APP_SECRET = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")

JWT_ALGORITHM = "HS256"
JWT_EXP_SECONDS = 3600  # 1 hour

# -----------------------------------------------------------------------------
# Database helpers
# -----------------------------------------------------------------------------

DB_PATH = "db.sqlite3"


def open_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    # Enforce foreign key constraints
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
    except sqlite3.DatabaseError:
        # Fallback: continue without raising here to avoid startup failure
        pass
    return conn


def init_db() -> None:
    conn = open_db_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                iterations INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                secret TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                UNIQUE(user_id),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# Password hashing (CWE-522 mitigation)
# -----------------------------------------------------------------------------

def hash_password(password: str) -> Tuple[str, str, int]:
    """
    Hash a password using PBKDF2-HMAC-SHA256 with a random salt.
    Returns (salt_b64, hash_b64, iterations).
    """
    if not isinstance(password, str):
        raise ValueError("Invalid password type")
    iterations = 310_000
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    salt_b64 = base64.b64encode(salt).decode("utf-8")
    hash_b64 = base64.b64encode(dk).decode("utf-8")
    return salt_b64, hash_b64, iterations


def verify_password(password: str, salt_b64: str, hash_b64: str, iterations: int) -> bool:
    try:
        salt = base64.b64decode(salt_b64.encode("utf-8"))
        expected = base64.b64decode(hash_b64.encode("utf-8"))
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(dk, expected)
    except Exception:
        # On any decoding or hashing error, do not reveal details; treat as invalid.
        return False


# -----------------------------------------------------------------------------
# JWT helpers (authorization)
# -----------------------------------------------------------------------------

def create_access_token(username: str, user_id: int) -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "uid": user_id,
        "iat": now,
        "exp": now + JWT_EXP_SECONDS,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_bearer_token_from_header(request: Request) -> Optional[str]:
    auth = request.headers.get("Authorization")
    if not auth:
        return None
    parts = auth.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1]


# -----------------------------------------------------------------------------
# Pydantic models (input validation)
# -----------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., min_length=3, max_length=64, examples=["user1"])
    password: str = Field(..., min_length=8, max_length=128, examples=["newUserPassword"])


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user@example.com"])
    password: str = Field(..., min_length=8, max_length=128, examples=["mySecretPassword"])


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, examples=["user1"])
    secret: str = Field(..., min_length=1, max_length=4096, examples=["mySecret"])


# -----------------------------------------------------------------------------
# FastAPI app and exception handlers
# -----------------------------------------------------------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Initialize DB at startup
@app.on_event("startup")
def on_startup():
    init_db()


# Custom exception handler for validation errors to return "message"
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=HTTP_400_BAD_REQUEST,
        content={"message": "Email already in use or invalid data"},
    )


# Catch-all exception handler (CWE-703 mitigation)
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "Internal server error"},
    )


# -----------------------------------------------------------------------------
# Endpoint implementations
# -----------------------------------------------------------------------------

@app.post("/register")
async def register(payload: RegisterRequest):
    conn = open_db_connection()
    try:
        # Check uniqueness (CWE-89 mitigation via parameterized queries)
        row = conn.execute(
            "SELECT id FROM users WHERE email = ? OR username = ?",
            (payload.email, payload.username),
        ).fetchone()
        if row is not None:
            return JSONResponse(
                status_code=HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )

        salt_b64, hash_b64, iterations = hash_password(payload.password)
        now = int(time.time())
        conn.execute(
            """
            INSERT INTO users (email, username, password_hash, password_salt, iterations, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (payload.email, payload.username, hash_b64, salt_b64, iterations, now),
        )
        return JSONResponse(
            status_code=HTTP_201_CREATED,
            content={"message": "Registration successful"},
        )
    except sqlite3.DatabaseError:
        # Do not leak DB errors
        return JSONResponse(
            status_code=HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )
    finally:
        conn.close()


@app.post("/login")
async def login(payload: LoginRequest):
    conn = open_db_connection()
    try:
        user = conn.execute(
            """
            SELECT id, username, password_hash, password_salt, iterations
            FROM users WHERE email = ?
            """,
            (payload.email,),
        ).fetchone()
        if user is None:
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
            )
        valid = verify_password(
            payload.password,
            user["password_salt"],
            user["password_hash"],
            int(user["iterations"]),
        )
        if not valid:
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
            )

        token = create_access_token(username=user["username"], user_id=int(user["id"]))
        return JSONResponse(
            status_code=HTTP_200_OK,
            content={"token": token, "message": "Login successful"},
        )
    finally:
        conn.close()


def auth_dependency(request: Request) -> Dict[str, Any]:
    """
    Authorization dependency to enforce bearer token and return claims.
    Mitigates CWE-284 / CWE-863 by enforcing access control.
    """
    token = get_bearer_token_from_header(request)
    if not token:
        # Missing or malformed token
        raise_auth_error()
    claims = decode_token(token)
    if not claims or "sub" not in claims or "uid" not in claims:
        raise_auth_error()
    # Return minimal claims without hitting DB again
    return {"username": claims["sub"], "uid": int(claims["uid"])}


def raise_auth_error():
    # Helper to return 401 with required message
    # Using exception and handler to standardize output
    raise AuthException()


class AuthException(Exception):
    pass


@app.exception_handler(AuthException)
async def auth_exception_handler(request: Request, exc: AuthException):
    return JSONResponse(
        status_code=HTTP_401_UNAUTHORIZED,
        content={"message": "Invalid authentication token"},
    )


@app.post("/set_secret")
async def set_secret(payload: SetSecretRequest, auth: Dict[str, Any] = Depends(auth_dependency)):
    # Enforce that the token's subject matches the requested username (CWE-863)
    if payload.username != auth["username"]:
        raise_auth_error()

    conn = open_db_connection()
    try:
        # Ensure user exists (defensive check)
        user = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (payload.username,),
        ).fetchone()
        if user is None or int(user["id"]) != auth["uid"]:
            # Token does not correspond to an existing user
            raise_auth_error()

        now = int(time.time())
        # Upsert secret atomically (CWE-89 mitigation via parameterized query)
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret = excluded.secret,
                updated_at = excluded.updated_at
            """,
            (auth["uid"], payload.secret, now),
        )
        return JSONResponse(
            status_code=HTTP_200_OK,
            content={"message": "Secret has been set successfully"},
        )
    finally:
        conn.close()


@app.get("/get_secret")
async def get_secret(username: str, auth: Dict[str, Any] = Depends(auth_dependency)):
    # Enforce that the token's subject matches the requested username (CWE-863)
    if username != auth["username"]:
        raise_auth_error()

    conn = open_db_connection()
    try:
        # Defensive: ensure user exists and matches uid
        user = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if user is None or int(user["id"]) != auth["uid"]:
            raise_auth_error()

        row = conn.execute(
            "SELECT secret FROM secrets WHERE user_id = ?",
            (auth["uid"],),
        ).fetchone()
        secret_value = row["secret"] if row else ""
        return JSONResponse(
            status_code=HTTP_200_OK,
            content={"secret": secret_value},
        )
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# Run the app
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)