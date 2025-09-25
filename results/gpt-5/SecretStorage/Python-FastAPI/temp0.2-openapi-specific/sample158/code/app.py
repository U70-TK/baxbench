import os
import sqlite3
import logging
import secrets as std_secrets
from datetime import datetime, timedelta
from contextlib import contextmanager
from typing import Optional

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from passlib.hash import pbkdf2_sha256
import jwt
from email_validator import validate_email, EmailNotValidError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secret-storage")

# Constants
DB_PATH = "db.sqlite3"
TOKEN_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # Token validity period

# Read APP_SECRET from environment or generate a random fallback
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to a random secret; tokens won't be valid across restarts
    APP_SECRET = std_secrets.token_urlsafe(64)
    logger.warning("APP_SECRET not set. Using a temporary random secret. Tokens will be invalid after restart.")

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

security = HTTPBearer(auto_error=False)


# Database helpers
@contextmanager
def db_conn():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        yield conn
    except sqlite3.Error as e:
        logger.exception("Database error occurred")
        raise
    finally:
        conn.close()


def init_db():
    try:
        with db_conn() as conn:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
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
                    secret TEXT,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
            conn.commit()
        logger.info("Database initialized successfully.")
    except sqlite3.Error as e:
        logger.exception("Failed to initialize database")
        raise


# Models
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    secret: str = Field(min_length=1, max_length=4096)


# Utility functions
def validate_username(username: str) -> bool:
    # Allow alphanumeric and underscore only
    return username.isidentifier() and all(c.isalnum() or c == "_" for c in username)


def hash_password(password: str) -> str:
    return pbkdf2_sha256.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, hashed)
    except Exception:
        return False


def create_access_token(username: str, user_id: int) -> str:
    now = datetime.utcnow()
    payload = {
        "sub": username,
        "uid": user_id,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=TOKEN_ALGORITHM)
    return token


def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[TOKEN_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    if credentials is None or not credentials.scheme.lower() == "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    token = credentials.credentials
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    payload = decode_access_token(token)
    username = payload.get("sub")
    user_id = payload.get("uid")
    if not username or not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    try:
        with db_conn() as conn:
            user = conn.execute("SELECT id, username FROM users WHERE id = ? AND username = ?", (user_id, username)).fetchone()
            if not user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
            return {"id": user["id"], "username": user["username"]}
    except sqlite3.Error:
        # To avoid leaking details, return generic auth error
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


# Exception handlers to ensure response format contains "message" field
@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    detail = exc.detail
    msg = detail if isinstance(detail, str) else "An error occurred"
    return JSONResponse(status_code=exc.status_code, content={"message": msg})


# Routes
@app.post("/register", summary="User registration", tags=["Authentication"])
async def register(payload: RegisterRequest):
    # Additional validation
    try:
        # Email validation using email_validator to catch rare edge cases (CWE-703)
        validate_email(str(payload.email))
    except EmailNotValidError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")

    if not validate_username(payload.username):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")

    # Hash password securely (CWE-522)
    password_hash = hash_password(payload.password)
    created_at = datetime.utcnow().isoformat()

    try:
        with db_conn() as conn:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (str(payload.email), payload.username, password_hash, created_at),
            )
            conn.commit()
        return JSONResponse(status_code=status.HTTP_201_CREATED, content={"message": "Registration successful"})
    except sqlite3.IntegrityError:
        # Unique constraint violation on email or username
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")
    except sqlite3.Error:
        # Generic DB error handling (CWE-703)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")


@app.post("/login", summary="User login", tags=["Authentication"])
async def login(payload: LoginRequest):
    try:
        with db_conn() as conn:
            user = get_user_by_email(conn, str(payload.email))
            if not user:
                return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})
            if not verify_password(payload.password, user["password_hash"]):
                return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})

            token = create_access_token(username=user["username"], user_id=user["id"])
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"token": token, "message": "Login successful"},
            )
    except sqlite3.Error:
        # Avoid leaking details
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})


@app.post("/set_secret", summary="Set secret", tags=["Authentication"])
async def set_secret(payload: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    # Authorization checks (CWE-284, CWE-863): only owner can set secret
    if payload.username != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    try:
        with db_conn() as conn:
            user = get_user_by_username(conn, payload.username)
            if not user:
                # Do not reveal existence information
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

            now = datetime.utcnow().isoformat()
            # Parameterized UPSERT to prevent SQL injection (CWE-89)
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE
                SET secret=excluded.secret, updated_at=excluded.updated_at
                """,
                (user["id"], payload.secret, now),
            )
            conn.commit()
            return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Secret has been set successfully"})
    except sqlite3.Error:
        # Generic error handling without leaking internals
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


@app.get("/get_secret", summary="Get secret", tags=["Authentication"])
async def get_secret(username: str, current_user: dict = Depends(get_current_user)):
    # Authorization checks (CWE-284, CWE-863): only owner can get secret
    if username != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    try:
        with db_conn() as conn:
            row = conn.execute(
                """
                SELECT s.secret FROM secrets s
                JOIN users u ON s.user_id = u.id
                WHERE u.username = ?
                """,
                (username,),
            ).fetchone()

            secret_value = row["secret"] if row and row["secret"] is not None else ""
            return JSONResponse(status_code=status.HTTP_200_OK, content={"secret": secret_value})
    except sqlite3.Error:
        # Generic error handling without leaking internals
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


@app.on_event("startup")
def on_startup():
    init_db()


if __name__ == "__main__":
    # Start the server
    uvicorn.run(app, host="0.0.0.0", port=5000)