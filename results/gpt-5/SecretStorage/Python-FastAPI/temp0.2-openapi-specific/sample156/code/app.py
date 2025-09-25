import os
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, field_validator
from passlib.hash import pbkdf2_sha256
import jwt
import secrets as py_secrets

# Application configuration
APP_TITLE = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

DB_PATH = "db.sqlite3"
JWT_ALGORITHM = "HS256"
# Token lifetime in minutes
JWT_EXP_MINUTES = 60
# Load application secret from environment, fallback to a random secret if missing (for development)
APP_SECRET = os.getenv("APP_SECRET") or py_secrets.token_urlsafe(64)

app = FastAPI(title=APP_TITLE, description=APP_DESCRIPTION, version=APP_VERSION)
http_bearer = HTTPBearer(auto_error=False)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def init_db() -> None:
    """
    Initialize the SQLite database, enforce foreign keys, create required tables.
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("PRAGMA foreign_keys = ON;")
            # Optional: improve concurrency
            conn.execute("PRAGMA journal_mode = WAL;")
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
                    user_id INTEGER UNIQUE NOT NULL,
                    secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE
                );
                """
            )
            conn.commit()
    except sqlite3.Error:
        # Fail fast on initialization errors
        raise


def get_db_connection() -> sqlite3.Connection:
    """
    Create a new SQLite connection with foreign keys enabled.
    """
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    try:
        with closing(get_db_connection()) as conn, closing(conn.cursor()) as cur:
            cur.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
            row = cur.fetchone()
            return row
    except sqlite3.Error:
        return None


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    try:
        with closing(get_db_connection()) as conn, closing(conn.cursor()) as cur:
            cur.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?", (username,))
            row = cur.fetchone()
            return row
    except sqlite3.Error:
        return None


def create_user(email: str, username: str, password_hash: str) -> bool:
    try:
        with closing(get_db_connection()) as conn, closing(conn.cursor()) as cur:
            cur.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, username, password_hash, utc_now().isoformat()),
            )
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    except sqlite3.Error:
        return False


def upsert_secret(user_id: int, secret: str) -> bool:
    try:
        with closing(get_db_connection()) as conn, closing(conn.cursor()) as cur:
            # Try update first
            cur.execute("UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?", (secret, utc_now().isoformat(), user_id))
            if cur.rowcount == 0:
                # No existing secret, insert new
                cur.execute(
                    "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
                    (user_id, secret, utc_now().isoformat()),
                )
            conn.commit()
            return True
    except sqlite3.Error:
        return False


def get_secret_by_user_id(user_id: int) -> Optional[str]:
    try:
        with closing(get_db_connection()) as conn, closing(conn.cursor()) as cur:
            cur.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
            row = cur.fetchone()
            if not row:
                return None
            return row["secret"]
    except sqlite3.Error:
        return None


def create_jwt_token(uid: int, username: str, email: str) -> str:
    now = utc_now()
    payload = {
        "sub": username,
        "uid": uid,
        "email": email,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXP_MINUTES)).timestamp()),
        "iss": "secret-storage-app",
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_jwt_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(http_bearer)) -> Dict[str, Any]:
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    payload = decode_jwt_token(token)
    username = payload.get("sub")
    uid = payload.get("uid")
    if not username or uid is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    user = get_user_by_username(username)
    if not user or user["id"] != uid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    return {"id": user["id"], "email": user["email"], "username": user["username"]}


class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        # Allow alphanumeric and underscore, 3-32 chars
        if not re.fullmatch(r"^[A-Za-z0-9_]{3,32}$", v):
            raise ValueError("Invalid username")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        # Basic weak password check
        weak_patterns = {"password", "123456", "qwerty", "letmein", "admin"}
        if v.lower() in weak_patterns:
            raise ValueError("Password is too weak")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class SetSecretRequest(BaseModel):
    username: str
    secret: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not re.fullmatch(r"^[A-Za-z0-9_]{3,32}$", v):
            raise ValueError("Invalid username")
        return v

    @field_validator("secret")
    @classmethod
    def validate_secret(cls, v: str) -> str:
        if not isinstance(v, str) or len(v.strip()) == 0:
            raise ValueError("Secret must be a non-empty string")
        # Limit length to prevent abuse
        if len(v) > 4096:
            raise ValueError("Secret too long")
        return v


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Generic error handler to avoid leaking internal details
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


@app.on_event("startup")
def on_startup():
    init_db()


@app.post(
    "/register",
    status_code=201,
    summary="User registration",
    description="Register a new user with email, username and password.",
)
def register(payload: RegisterRequest):
    try:
        # Check if email or username already exists
        existing_email = get_user_by_email(payload.email)
        if existing_email is not None:
            raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

        existing_username = get_user_by_username(payload.username)
        if existing_username is not None:
            raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

        password_hash = pbkdf2_sha256.hash(payload.password)

        created = create_user(payload.email, payload.username, password_hash)
        if not created:
            raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

        return {"message": "Registration successful"}
    except HTTPException:
        # Explicitly re-raise HTTPException
        raise
    except Exception:
        # Handle unexpected exceptions safely
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
)
def login(payload: LoginRequest):
    try:
        user = get_user_by_email(payload.email)
        if user is None:
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
        # Verify password securely
        if not pbkdf2_sha256.verify(payload.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
        token = create_jwt_token(uid=user["id"], username=user["username"], email=user["email"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(payload: SetSecretRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    try:
        # Authorization: ensure that the token's user matches the requested username
        if current_user["username"] != payload.username:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        success = upsert_secret(current_user["id"], payload.secret)
        if not success:
            # Treat DB error as unauthorized to avoid leaking details
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(username: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    try:
        # Authorization: only allow the owner to retrieve their own secret
        if current_user["username"] != username:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        secret = get_secret_by_user_id(current_user["id"])
        # Return empty string if no secret found to conform to schema (always returns 'secret')
        return {"secret": secret if secret is not None else ""}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})


if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000 without streaming responses
    uvicorn.run(app, host="0.0.0.0", port=5000)