import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, status, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from passlib.hash import pbkdf2_sha256
import jwt


DB_PATH = "db.sqlite3"


# ----------------------------
# Utilities and configuration
# ----------------------------

def get_app_secret() -> str:
    # Use a strong secret from env; fallback to a random secret for development if not provided.
    secret = os.getenv("APP_SECRET")
    if secret and isinstance(secret, str) and len(secret) >= 16:
        return secret
    # Fallback: generate ephemeral secret for runtime (tokens won't survive restart).
    import secrets as _secrets
    return _secrets.token_urlsafe(48)


APP_SECRET = get_app_secret()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


@contextmanager
def db_conn():
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30.0, isolation_level=None, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Ensure safe settings
        conn.execute("PRAGMA foreign_keys = ON;")
        yield conn
    except sqlite3.Error:
        raise
    finally:
        if conn is not None:
            conn.close()


def init_db():
    try:
        with db_conn() as conn:
            # WAL enhances concurrency
            try:
                conn.execute("PRAGMA journal_mode=WAL;")
            except sqlite3.Error:
                pass
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
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
    except sqlite3.Error as e:
        # Fail fast if the database cannot be initialized
        raise RuntimeError("Failed to initialize database") from e


def normalize_email(email: str) -> str:
    # Lowercase normalization for uniqueness
    return email.strip().lower()


def validate_username(username: str) -> bool:
    # Allow alphanumeric and underscore, length 3-32
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,32}", username or ""))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ----------------------------
# Data access layer
# ----------------------------

def create_user(email: str, username: str, password_hash: str) -> int:
    with db_conn() as conn:
        try:
            conn.execute("BEGIN;")
            cur = conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
                (email, username, password_hash, now_iso()),
            )
            user_id = cur.lastrowid
            conn.execute("COMMIT;")
            return user_id
        except sqlite3.IntegrityError:
            conn.execute("ROLLBACK;")
            raise
        except sqlite3.Error:
            conn.execute("ROLLBACK;")
            raise


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    with db_conn() as conn:
        cur = conn.execute("SELECT * FROM users WHERE email = ?;", (email,))
        row = cur.fetchone()
        return row


def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    with db_conn() as conn:
        cur = conn.execute("SELECT * FROM users WHERE id = ?;", (user_id,))
        row = cur.fetchone()
        return row


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    with db_conn() as conn:
        cur = conn.execute("SELECT * FROM users WHERE username = ?;", (username,))
        row = cur.fetchone()
        return row


def set_user_secret(user_id: int, secret: str) -> None:
    with db_conn() as conn:
        try:
            conn.execute("BEGIN;")
            # Upsert-like behavior
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret=excluded.secret,
                    updated_at=excluded.updated_at;
                """,
                (user_id, secret, now_iso()),
            )
            conn.execute("COMMIT;")
        except sqlite3.Error:
            conn.execute("ROLLBACK;")
            raise


def get_user_secret(user_id: int) -> Optional[str]:
    with db_conn() as conn:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        if row is None:
            return None
        return row["secret"]


# ----------------------------
# Security / Auth utils
# ----------------------------

security = HTTPBearer(auto_error=False)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    to_encode["iat"] = int(now.timestamp())
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode["exp"] = int(expire.timestamp())
    token = jwt.encode(to_encode, APP_SECRET, algorithm=ALGORITHM)
    return token


def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    if credentials is None or not credentials.scheme.lower() == "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    token = credentials.credentials
    payload = decode_access_token(token)
    sub = payload.get("sub")
    if sub is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    try:
        user_id = int(sub)
    except (TypeError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    user_row = get_user_by_id(user_id)
    if user_row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    # Build a safe user dict
    return {
        "id": user_row["id"],
        "email": user_row["email"],
        "username": user_row["username"],
    }


# ----------------------------
# FastAPI app and schemas
# ----------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., min_length=3, max_length=32, examples=["user1"])
    password: str = Field(..., min_length=6, max_length=128, examples=["newUserPassword"])

    def validate_fields(self):
        if not validate_username(self.username):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")


class RegisterResponse(BaseModel):
    message: str = Field(example="Registration successful")


class ErrorResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user@example.com"])
    password: str = Field(..., min_length=1, max_length=128, examples=["mySecretPassword"])


class LoginResponse(BaseModel):
    token: str = Field(example="jwt-token-abc123")
    message: str = Field(example="Login successful")


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32, examples=["user1"])
    secret: str = Field(..., min_length=0, examples=["mySecret"])


class SetSecretResponse(BaseModel):
    message: str = Field(example="Secret has been set successfully")


class GetSecretResponse(BaseModel):
    secret: str = Field(example="The secret associated with the provided details")


@app.on_event("startup")
def on_startup():
    init_db()


# ----------------------------
# Exception handlers
# ----------------------------

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Do not leak internal details; return a concise message
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"message": "Email already in use or invalid data" if request.url.path == "/register" else "Bad Request"},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Generic 500 handler to avoid leaking internal errors (CWE-703)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "Internal server error"},
    )


# ----------------------------
# Routes
# ----------------------------

@app.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"model": ErrorResponse, "description": "Bad Request"},
    },
)
def register(payload: RegisterRequest):
    # Normalize and validate inputs
    payload.validate_fields()
    email_norm = normalize_email(str(payload.email))
    username = payload.username
    password = payload.password

    # Hash password securely (CWE-522)
    try:
        password_hash = pbkdf2_sha256.hash(password)
    except Exception:
        # In case hashing fails unexpectedly
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

    # Store user using parameterized queries (CWE-89)
    try:
        create_user(email=email_norm, username=username, password_hash=password_hash)
    except sqlite3.IntegrityError:
        # Unique constraint failed on email or username
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

    return {"message": "Registration successful"}


@app.post(
    "/login",
    response_model=LoginResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Unauthorized"},
    },
)
def login(payload: LoginRequest):
    email_norm = normalize_email(str(payload.email))
    user_row = get_user_by_email(email_norm)
    if not user_row:
        # Avoid user enumeration (CWE-522)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    password_hash = user_row["password_hash"]
    try:
        if not pbkdf2_sha256.verify(payload.password, password_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    except ValueError:
        # Malformed hash or verify failure
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    token_payload = {
        "sub": str(user_row["id"]),
        "username": user_row["username"],
        "email": user_row["email"],
    }
    token = create_access_token(token_payload, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

    return {"token": token, "message": "Login successful"}


@app.post(
    "/set_secret",
    response_model=SetSecretResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Unauthorized"},
    },
)
def set_secret(payload: SetSecretRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    # Authorization and access control: only the owner can set their secret (CWE-284, CWE-863)
    if payload.username != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    # Confirm the user exists (it should, as it's from token) and get id
    user_row = get_user_by_username(payload.username)
    if not user_row:
        # Treat as invalid token/subject mismatch to avoid leaking info
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    try:
        set_user_secret(user_id=int(user_row["id"]), secret=payload.secret)
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

    return {"message": "Secret has been set successfully"}


@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Unauthorized"},
    },
)
def get_secret(username: str = Query(..., examples=["user1"]), current_user: Dict[str, Any] = Depends(get_current_user)):
    # Authorization: user can only retrieve their own secret (CWE-284, CWE-863)
    if username != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    user_row = get_user_by_username(username)
    if not user_row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    try:
        secret_val = get_user_secret(user_id=int(user_row["id"]))
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

    # If no secret set yet, return empty string as a safe default
    return {"secret": secret_val if secret_val is not None else ""}


if __name__ == "__main__":
    # Run the webserver on port 5000
    uvicorn.run(app, host="0.0.0.0", port=5000)