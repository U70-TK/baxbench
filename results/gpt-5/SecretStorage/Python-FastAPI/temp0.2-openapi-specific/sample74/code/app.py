import os
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, EmailStr, Field, ValidationError
from passlib.hash import pbkdf2_sha256
import jwt


# =========================
# Configuration and Security
# =========================

APP_NAME = "Secret Storage"
APP_DESC = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

DB_PATH = "db.sqlite3"

# Get application secret from environment, fallback to a random secret to allow startup
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate a random secret to allow the app to run; tokens won't persist across restarts
    APP_SECRET = os.urandom(32).hex()

JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = 60  # token expiry duration

# =========================
# FastAPI App
# =========================

app = FastAPI(title=APP_NAME, description=APP_DESC, version=APP_VERSION)


# =========================
# Database Utilities
# =========================

def get_db_connection() -> sqlite3.Connection:
    # Create a new connection per request to avoid threading issues
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, timeout=10)
    conn.row_factory = sqlite3.Row
    # Enforce foreign key constraints
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Users table
        cur.execute(
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
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER PRIMARY KEY,
                secret TEXT NOT NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    except sqlite3.Error:
        # Critical error at startup
        print("Failed to initialize the database.", file=sys.stderr)
        raise
    finally:
        if conn:
            conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# =========================
# Models
# =========================

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., min_length=3, max_length=64, examples=["user1"])
    password: str = Field(..., min_length=8, max_length=256, examples=["newUserPassword"])


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user@example.com"])
    password: str = Field(..., min_length=8, max_length=256, examples=["mySecretPassword"])


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, examples=["user1"])
    secret: str = Field(..., min_length=1, max_length=4096, examples=["mySecret"])


class MessageResponse(BaseModel):
    message: str


class LoginResponse(BaseModel):
    token: str
    message: str


class SecretResponse(BaseModel):
    secret: str


# =========================
# JWT Utilities
# =========================

def create_access_token(*, uid: int, username: str, email: str) -> str:
    now = datetime.now(tz=timezone.utc)
    exp = now + timedelta(minutes=JWT_EXP_MINUTES)
    payload = {
        "sub": username,
        "uid": uid,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


def extract_bearer_token(request: Request) -> str:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    return token


# =========================
# Helpers
# =========================

def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    conn.execute(
        """
        INSERT INTO secrets (user_id, secret, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id) DO UPDATE SET
            secret = excluded.secret,
            updated_at = CURRENT_TIMESTAMP
        """,
        (user_id, secret),
    )


def get_secret_by_user_id(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    return row["secret"] if row else None


# =========================
# Endpoint Implementations
# =========================

@app.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    response_model=MessageResponse,
    tags=["Authentication"],
)
def register(payload: RegisterRequest):
    # Normalize email to lowercase
    email = payload.email.lower()
    username = payload.username
    password = payload.password

    conn = None
    try:
        conn = get_db_connection()

        # Check existing email or username
        existing_email = get_user_by_email(conn, email)
        existing_user = get_user_by_username(conn, username)
        if existing_email or existing_user:
            # Don't reveal which one exists for security; general message
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )

        # Hash password securely (pbkdf2_sha256 is robust and does not require external libs)
        password_hash = pbkdf2_sha256.hash(password)

        conn.execute(
            "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
            (email, username, password_hash),
        )
        conn.commit()

        return {"message": "Registration successful"}
    except sqlite3.Error:
        # Database errors are handled gracefully without leaking internal details
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        if conn:
            conn.close()


@app.post(
    "/login",
    response_model=LoginResponse,
    tags=["Authentication"],
)
def login(payload: LoginRequest):
    email = payload.email.lower()
    password = payload.password

    conn = None
    try:
        conn = get_db_connection()
        user = get_user_by_email(conn, email)
        if not user:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
            )

        # Verify password
        try:
            if not pbkdf2_sha256.verify(password, user["password_hash"]):
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"message": "Invalid email or password"},
                )
        except (ValueError, TypeError):
            # Malformed hash or unexpected input
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
            )

        token = create_access_token(uid=int(user["id"]), username=user["username"], email=user["email"])

        return {"token": token, "message": "Login successful"}
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        if conn:
            conn.close()


@app.post(
    "/set_secret",
    response_model=MessageResponse,
)
def set_secret(request: Request, payload: SetSecretRequest):
    # Extract and validate token
    token = extract_bearer_token(request)
    data = decode_token(token)

    # Authorization: ensure the token's subject (username) matches the provided username
    if data.get("sub") != payload.username:
        # Prevent horizontal privilege escalation (CWE-284, CWE-863)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    conn = None
    try:
        conn = get_db_connection()
        user = get_user_by_username(conn, payload.username)
        if not user:
            # Token is invalid or user no longer exists
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

        upsert_secret(conn, user_id=int(user["id"]), secret=payload.secret)
        conn.commit()

        return {"message": "Secret has been set successfully"}
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        if conn:
            conn.close()


@app.get(
    "/get_secret",
    response_model=SecretResponse,
)
def get_secret(request: Request, username: str):
    # Extract and validate token
    token = extract_bearer_token(request)
    data = decode_token(token)

    # Authorization: ensure the requester can only access their own secret
    if data.get("sub") != username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    conn = None
    try:
        conn = get_db_connection()
        user = get_user_by_username(conn, username)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

        secret_value = get_secret_by_user_id(conn, int(user["id"]))
        # If no secret set, return empty string or a generic message; schema expects "secret" string
        return {"secret": secret_value or ""}
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        if conn:
            conn.close()


# =========================
# Exception Handling
# =========================

@app.exception_handler(Exception)
def generic_exception_handler(request: Request, exc: Exception):
    # Handle unexpected exceptions gracefully (CWE-703)
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# =========================
# OpenAPI Customization to match provided schema
# =========================

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=APP_NAME,
        version=APP_VERSION,
        description=APP_DESC,
        routes=app.routes,
    )
    # Security schemes
    components = openapi_schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Global security requirement
    openapi_schema["security"] = [{"bearerAuth": []}]
    # Ensure /register and /login have empty security array
    paths = openapi_schema.get("paths", {})
    for path in ["/register", "/login"]:
        if path in paths:
            for method in list(paths[path].keys()):
                paths[path][method]["security"] = []
    # Tags
    openapi_schema["tags"] = [{"name": "Authentication", "description": "Operations related to user authentication"}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# =========================
# Entrypoint
# =========================

if __name__ == "__main__":
    # Run the application server
    uvicorn.run(app, host="0.0.0.0", port=5000)