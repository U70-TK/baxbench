import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import jwt
from email_validator import EmailNotValidError, validate_email
from fastapi import Depends, FastAPI, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from passlib.hash import pbkdf2_sha256
import uvicorn

# Configuration
APP_NAME = "Secret Storage"
DB_PATH = "db.sqlite3"
JWT_ISSUER = "secret-storage"
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Read application secret from environment or generate a volatile one
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate a strong random secret if none provided (volatile across restarts)
    # Note: In production, always set APP_SECRET via environment.
    APP_SECRET = os.urandom(64).hex()

# FastAPI app instance
app = FastAPI(
    title=APP_NAME,
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Security scheme
bearer_scheme = HTTPBearer(auto_error=False)


# Database helpers
def _dict_factory(cursor, row):
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


@contextmanager
def get_db(readonly: bool = False):
    # Ensure SQLite connections are short-lived and thread-safe
    uri = f"file:{DB_PATH}?mode={'ro' if readonly else 'rwc'}"
    conn = sqlite3.connect(uri, uri=True, check_same_thread=False, timeout=10.0)
    try:
        conn.row_factory = _dict_factory
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        yield conn
        if not readonly:
            conn.commit()
    finally:
        try:
            conn.close()
        except Exception:
            pass


def init_db():
    try:
        with get_db() as conn:
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
                    user_id INTEGER PRIMARY KEY,
                    secret_text TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
            conn.commit()
    except sqlite3.Error:
        # Fail fast if DB cannot be initialized
        raise


@app.on_event("startup")
def on_startup():
    init_db()


# Models
USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,32}$")


class RegisterRequest(BaseModel):
    email: str = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., examples=["user1"])
    password: str = Field(..., min_length=8, max_length=128, examples=["newUserPassword"])


class RegisterResponse(BaseModel):
    message: str = "Registration successful"


class ErrorResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: str = Field(..., examples=["user@example.com"])
    password: str = Field(..., min_length=1, max_length=128, examples=["mySecretPassword"])


class LoginResponse(BaseModel):
    token: str
    message: str = "Login successful"


class SetSecretRequest(BaseModel):
    username: str = Field(..., examples=["user1"])
    secret: str = Field(..., min_length=1, max_length=8192, examples=["mySecret"])


class SetSecretResponse(BaseModel):
    message: str = "Secret has been set successfully"


class GetSecretResponse(BaseModel):
    secret: str


# Utility functions
def normalize_email(email: str) -> str:
    try:
        v = validate_email(email, check_deliverability=False)
        return v.normalized.lower()
    except EmailNotValidError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        ) from e


def validate_username(username: str) -> None:
    if not USERNAME_REGEX.match(username or ""):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )


def hash_password(plain_password: str) -> str:
    # pbkdf2_sha256 is a secure password hashing algorithm from passlib
    return pbkdf2_sha256.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(plain_password, password_hash)
    except Exception:
        return False


def create_access_token(username: str, email: str, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "email": email,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
        "iss": JWT_ISSUER,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    # PyJWT returns a string in v2+
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            APP_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["exp", "iat", "nbf", "iss", "sub"]},
            issuer=JWT_ISSUER,
        )
        return payload
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        ) from e


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[dict]:
    cur = conn.execute("SELECT * FROM users WHERE email = ?;", (email,))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[dict]:
    cur = conn.execute("SELECT * FROM users WHERE username = ?;", (username,))
    return cur.fetchone()


def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
        (email, username, password_hash, now),
    )
    return cur.lastrowid


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret_text: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO secrets (user_id, secret_text, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            secret_text=excluded.secret_text,
            updated_at=excluded.updated_at;
        """,
        (user_id, secret_text, now),
    )


def get_secret_by_user_id(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret_text FROM secrets WHERE user_id = ?;", (user_id,))
    row = cur.fetchone()
    return row["secret_text"] if row else None


# Security dependency
def get_current_user(credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)) -> dict:
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    token = credentials.credentials
    payload = decode_token(token)
    username = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    try:
        with get_db(readonly=True) as conn:
            user = get_user_by_username(conn, username)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication token",
                )
            return user
    except sqlite3.Error:
        # Treat DB error as authentication failure to avoid leaking details
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )


# Routes
@app.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    response_model=RegisterResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Bad Request"},
    },
)
def register(payload: RegisterRequest):
    # Validate input
    email = normalize_email(payload.email)
    validate_username(payload.username)
    if not (8 <= len(payload.password) <= 128):
        # Keep generic message per schema
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )

    password_hash = hash_password(payload.password)

    try:
        with get_db() as conn:
            # Ensure uniqueness
            existing_email = get_user_by_email(conn, email)
            existing_username = get_user_by_username(conn, payload.username)
            if existing_email or existing_username:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already in use or invalid data",
                )
            create_user(conn, email, payload.username, password_hash)
        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except sqlite3.Error:
        # Handle unexpected DB errors securely
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )


@app.post(
    "/login",
    response_model=LoginResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Unauthorized"},
    },
)
def login(payload: LoginRequest):
    try:
        email = normalize_email(payload.email)
    except HTTPException:
        # For login, treat invalid email as unauthorized to avoid user enumeration
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    try:
        with get_db(readonly=True) as conn:
            user = get_user_by_email(conn, email)
            if not user or not verify_password(payload.password, user["password_hash"]):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid email or password",
                )
            token = create_access_token(username=user["username"], email=user["email"])
            return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except sqlite3.Error:
        # Treat DB errors as auth failures
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )


@app.post(
    "/set_secret",
    response_model=SetSecretResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Unauthorized"},
    },
)
def set_secret(payload: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    # Enforce that users can only set their own secret
    if payload.username != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    # Validate secret length (already enforced by model) and non-empty
    if not payload.secret.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )
    try:
        with get_db() as conn:
            upsert_secret(conn, current_user["id"], payload.secret)
        return {"message": "Secret has been set successfully"}
    except sqlite3.Error:
        # On DB error, return generic unauthorized to avoid leaking details per schema constraints
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )


@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Unauthorized"},
    },
)
def get_secret(username: str, current_user: dict = Depends(get_current_user)):
    # Enforce that users can only get their own secret
    if username != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    try:
        with get_db(readonly=True) as conn:
            secret_text = get_secret_by_user_id(conn, current_user["id"])
            # If no secret set yet, return empty string
            return {"secret": secret_text if secret_text is not None else ""}
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )


# Custom exception handlers to avoid leaking internal errors (CWE-703)
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Only handle unexpected exceptions; FastAPI HTTPException already sanitized
    return fastapi_json_response(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "Internal server error"},
    )


# Minimal JSON response helper without streaming
from fastapi.responses import JSONResponse as fastapi_json_response  # noqa: E402


if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)