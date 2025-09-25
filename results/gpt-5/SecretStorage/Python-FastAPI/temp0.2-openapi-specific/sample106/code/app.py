import os
import re
import sqlite3
import secrets
import hmac
import hashlib
import datetime
from typing import Optional, Tuple

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, ValidationError

import jwt  # from pyjwt

DB_PATH = "db.sqlite3"

# Load application secret
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Generate a strong random secret if not provided (ephemeral)
    APP_SECRET = secrets.token_urlsafe(64)

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Security dependency for Bearer tokens
bearer_scheme = HTTPBearer(auto_error=False)


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    with conn:  # ensure PRAGMAs applied immediately
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    return conn


def init_db() -> None:
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT NOT NULL DEFAULT '',
                    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
    except sqlite3.DatabaseError:
        # In case of DB init failure, raise an exception to avoid running in inconsistent state
        raise
    finally:
        conn.close()


# Password hashing helpers using PBKDF2-HMAC (standard library)
def hash_password(password: str, iterations: int = 200_000) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iter_str, salt_hex, hash_hex = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iter_str)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


# JWT helpers
def create_access_token(sub: str) -> str:
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    exp = now + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": sub,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM], options={"require": ["exp", "iat", "nbf"]})
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


async def get_current_subject(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)) -> str:
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    token = credentials.credentials
    payload = decode_token(token)
    sub = payload.get("sub")
    if not sub or not isinstance(sub, str):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    return sub


# Pydantic models
USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,32}$")


class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=128)

    def validate_username(self) -> None:
        if not USERNAME_REGEX.fullmatch(self.username):
            raise ValueError("Username must be 3-32 chars: letters, digits, underscore only")


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class RegisterResponse(BaseModel):
    message: str


class LoginResponse(BaseModel):
    token: str
    message: str


class MessageResponse(BaseModel):
    message: str


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    secret: str = Field(min_length=0, max_length=4096)


class GetSecretResponse(BaseModel):
    secret: str


# Utility DB functions
def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?;", (email,))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?;", (username,))
    return cur.fetchone()


def create_user(conn: sqlite3.Connection, email: str, username: str, password: str) -> None:
    pwd_hash = hash_password(password)
    with conn:
        conn.execute(
            "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?);",
            (email, username, pwd_hash),
        )


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    with conn:
        # Upsert secret for the user
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id)
            DO UPDATE SET secret = excluded.secret, updated_at = CURRENT_TIMESTAMP;
            """,
            (user_id, secret),
        )


def fetch_secret(conn: sqlite3.Connection, user_id: int) -> str:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
    row = cur.fetchone()
    return row["secret"] if row and row["secret"] is not None else ""


# Exception handlers for robustness (CWE-703)
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Do not leak internal details
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


@app.on_event("startup")
def on_startup():
    init_db()


@app.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
)
async def register(payload: RegisterRequest):
    # Extra validation for username characters
    try:
        payload.validate_username()
    except ValueError:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )

    conn = get_db_connection()
    try:
        # Check existing email or username
        existing_email = get_user_by_email(conn, payload.email)
        existing_username = get_user_by_username(conn, payload.username)
        if existing_email is not None or existing_username is not None:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )
        # Create user
        create_user(conn, payload.email, payload.username, payload.password)
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Unique constraint violation or similar
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )
    except sqlite3.DatabaseError:
        # DB error
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )
    finally:
        conn.close()


@app.post(
    "/login",
    response_model=LoginResponse,
    tags=["Authentication"],
)
async def login(payload: LoginRequest):
    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, payload.email)
        if user is None:
            # Avoid user enumeration
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password"
            )
        if not verify_password(payload.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password"
            )
        token = create_access_token(sub=user["username"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        # Generic failure should not leak info
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    finally:
        conn.close()


@app.post(
    "/set_secret",
    response_model=MessageResponse,
)
async def set_secret(payload: SetSecretRequest, subject: str = Depends(get_current_subject)):
    # Authorization: the subject in token must match the username in the request
    if subject != payload.username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, payload.username)
        if user is None:
            # Treat as unauthorized access to avoid leaking info
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        upsert_secret(conn, user_id=user["id"], secret=payload.secret)
        return {"message": "Secret has been set successfully"}
    finally:
        conn.close()


@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
)
async def get_secret(username: str, subject: str = Depends(get_current_subject)):
    # Authorization: token subject must match the requested username
    if subject != username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, username)
        if user is None:
            # Avoid leaking whether user exists
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        secret_text = fetch_secret(conn, user_id=user["id"])
        return {"secret": secret_text}
    finally:
        conn.close()


# Custom handlers to align with required response shape on 401
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # For 401, return {"message": "..."} to match the schema examples
    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
        msg = exc.detail if isinstance(exc.detail, str) else "Invalid authentication token"
        return JSONResponse(status_code=exc.status_code, content={"message": msg})
    if exc.status_code == status.HTTP_403_FORBIDDEN:
        # Consistent JSON response
        return JSONResponse(status_code=exc.status_code, content={"message": "Forbidden"})
    # Default behavior for others
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)