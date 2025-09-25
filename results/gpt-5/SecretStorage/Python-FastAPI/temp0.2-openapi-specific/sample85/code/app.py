import os
import re
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Header, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, ValidationError
import jwt  # pyjwt
from passlib.hash import pbkdf2_sha256

DB_PATH = "db.sqlite3"

# Load application secret for signing JWTs
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate a fallback random secret for runtime if not provided; this is ephemeral.
    # In production, always provide APP_SECRET via environment variable.
    APP_SECRET = os.urandom(32).hex()

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Initialize FastAPI app
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


# Database utilities

def _init_db_schema(conn: sqlite3.Connection) -> None:
    # Enable foreign keys and reasonable journaling
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    # Create tables
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
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )
    # Indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")


@contextmanager
def get_db_conn():
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH, timeout=15, isolation_level=None)  # autocommit mode
        conn.row_factory = sqlite3.Row
        _init_db_schema(conn)
        yield conn
    except sqlite3.Error as e:
        # Handle database-level exceptions generically
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        if conn:
            conn.close()


# Security utilities

def create_access_token(*, subject_username: str, user_id: int, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(tz=timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode = {
        "sub": subject_username,
        "uid": user_id,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(to_encode, APP_SECRET, algorithm=ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def extract_bearer_token(authorization: Optional[str]) -> str:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return parts[1]


# Models

USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,50}$")


class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., examples=["user1"])
    password: str = Field(..., min_length=8, examples=["newUserPassword"])

    def normalized(self) -> Tuple[str, str, str]:
        email = self.email.strip().lower()
        username = self.username.strip()
        password = self.password
        return email, username, password


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user@example.com"])
    password: str = Field(..., min_length=1, examples=["mySecretPassword"])

    def normalized(self) -> Tuple[str, str]:
        return self.email.strip().lower(), self.password


class SetSecretRequest(BaseModel):
    username: str = Field(..., examples=["user1"])
    secret: str = Field(..., min_length=1, examples=["mySecret"])


class RegisterResponse(BaseModel):
    message: str


class LoginResponse(BaseModel):
    token: str
    message: str


class SetSecretResponse(BaseModel):
    message: str


class GetSecretResponse(BaseModel):
    secret: str


# Helpers

def validate_username(username: str) -> None:
    if not USERNAME_REGEX.match(username):
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def create_user(conn: sqlite3.Connection, email: str, username: str, password: str) -> int:
    password_hash = pbkdf2_sha256.hash(password)
    now = datetime.now(timezone.utc).isoformat()
    try:
        cur = conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, now),
        )
        user_id = cur.lastrowid
        return int(user_id)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, password_hash)
    except Exception:
        return False


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret_text: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    try:
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=excluded.updated_at
            """,
            (user_id, secret_text, now),
        )
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")


def fetch_secret(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if row:
        return str(row["secret"])
    return None


# Exception handlers for robustness (CWE-703)

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Ensure consistent JSON structure and headers
    headers = getattr(exc, "headers", None)
    content = {"message": exc.detail if isinstance(exc.detail, str) else "An error occurred"}
    return JSONResponse(status_code=exc.status_code, content=content, headers=headers)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Do not leak internals
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# Routes

@app.post("/register", response_model=RegisterResponse, status_code=201, tags=["Authentication"])
def register(payload: RegisterRequest):
    try:
        email, username, password = payload.normalized()
        validate_username(username)
        with get_db_conn() as conn:
            # Ensure email and username are unique (handled by DB), but we can check early to reduce exceptions
            existing_email = get_user_by_email(conn, email)
            existing_username = get_user_by_username(conn, username)
            if existing_email or existing_username:
                raise HTTPException(status_code=400, detail="Email already in use or invalid data")
            create_user(conn, email, username, password)
            return {"message": "Registration successful"}
    except HTTPException:
        raise
    except ValidationError:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    except Exception:
        # Generic fallback
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/login", response_model=LoginResponse, tags=["Authentication"])
def login(payload: LoginRequest):
    try:
        email, password = payload.normalized()
        with get_db_conn() as conn:
            user = get_user_by_email(conn, email)
            if not user or not verify_password(password, user["password_hash"]):
                # Avoid revealing whether email or password is wrong
                raise HTTPException(status_code=401, detail="Invalid email or password")
            token = create_access_token(subject_username=user["username"], user_id=int(user["id"]))
            return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")


def authenticate_and_authorize(authorization: Optional[str], username_param: str) -> int:
    token = extract_bearer_token(authorization)
    payload = decode_token(token)
    sub = payload.get("sub")
    uid = payload.get("uid")
    if not sub or not uid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Authorization check: token subject must match the requested username
    if str(sub) != str(username_param):
        # To prevent user from accessing another user's data (CWE-284 / CWE-863)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Ensure the user still exists and consistency between uid and username
    with get_db_conn() as conn:
        user = get_user_by_username(conn, username_param)
        if not user or int(user["id"]) != int(uid):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )
    return int(uid)


@app.post("/set_secret", response_model=SetSecretResponse)
def set_secret(payload: SetSecretRequest, Authorization: Optional[str] = Header(default=None)):
    try:
        username = payload.username.strip()
        secret_text = payload.secret
        validate_username(username)
        user_id = authenticate_and_authorize(Authorization, username)
        with get_db_conn() as conn:
            upsert_secret(conn, user_id, secret_text)
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/get_secret", response_model=GetSecretResponse)
def get_secret(username: str, Authorization: Optional[str] = Header(default=None)):
    try:
        username = username.strip()
        validate_username(username)
        user_id = authenticate_and_authorize(Authorization, username)
        with get_db_conn() as conn:
            secret = fetch_secret(conn, user_id)
            if secret is None:
                # If no secret set, return empty or not found? Spec expects 200 with 'secret' string.
                secret = ""
            return {"secret": secret}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")


# Startup event to ensure DB is initialized
@app.on_event("startup")
def on_startup():
    try:
        with get_db_conn() as conn:
            # Already initialized in context manager
            pass
    except Exception:
        # Do not crash the app; log would be here if logging configured
        pass


if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)