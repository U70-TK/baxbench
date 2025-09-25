import os
import re
import sqlite3
import secrets as pysecrets
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt  # PyJWT
from fastapi import FastAPI, HTTPException, Security, Request, Depends, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.hash import pbkdf2_sha256
from pydantic import BaseModel, EmailStr, Field

# ------------------------------------------------------------------------------
# Configuration and Security
# ------------------------------------------------------------------------------

APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Generate a strong random secret for tokens if not provided; tokens will be invalidated on restart.
    APP_SECRET = pysecrets.token_urlsafe(64)
    print("WARNING: APP_SECRET not set. Using a random ephemeral secret for JWT. Set APP_SECRET for stability.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DB_PATH = "db.sqlite3"

# ------------------------------------------------------------------------------
# Database Utilities
# ------------------------------------------------------------------------------

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30.0, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Safety-related PRAGMA settings
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def init_db() -> None:
    with closing(get_db_connection()) as conn:
        with conn:  # transaction
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")


def create_user(email: str, username: str, password_hash: str) -> int:
    with closing(get_db_connection()) as conn:
        try:
            with conn:
                cur = conn.execute(
                    "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (email, username, password_hash, datetime.now(timezone.utc).isoformat()),
                )
                return cur.lastrowid
        except sqlite3.IntegrityError:
            # Unique constraint failure or other integrity issues
            raise


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    with closing(get_db_connection()) as conn:
        cur = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        return row


def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    with closing(get_db_connection()) as conn:
        cur = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        return row


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    with closing(get_db_connection()) as conn:
        cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        return row


def upsert_secret(user_id: int, secret: str) -> None:
    with closing(get_db_connection()) as conn:
        with conn:
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret = excluded.secret,
                    updated_at = excluded.updated_at
                """,
                (user_id, secret, datetime.now(timezone.utc).isoformat()),
            )


def get_secret_by_user_id(user_id: int) -> Optional[str]:
    with closing(get_db_connection()) as conn:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        return row["secret"] if row else None


# ------------------------------------------------------------------------------
# Pydantic Models
# ------------------------------------------------------------------------------

USERNAME_REGEX = r"^[A-Za-z0-9_]{3,30}$"

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=30, pattern=USERNAME_REGEX)
    password: str = Field(..., min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=128)


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=30, pattern=USERNAME_REGEX)
    secret: str = Field(..., min_length=0, max_length=10000)


# ------------------------------------------------------------------------------
# Auth Helpers
# ------------------------------------------------------------------------------

http_bearer = HTTPBearer(auto_error=False)

def create_access_token(*, user_id: int, username: str, expires_delta: Optional[timedelta] = None) -> str:
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
        "type": "access",
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(plain_password, password_hash)
    except (ValueError, TypeError):
        return False


def hash_password(plain_password: str) -> str:
    # pbkdf2_sha256 is a secure hash provided by passlib and requires no external dependencies.
    return pbkdf2_sha256.hash(plain_password)


async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Security(http_bearer)) -> sqlite3.Row:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    token = credentials.credentials
    payload = decode_token(token)
    user_id = payload.get("sub")
    username = payload.get("username")
    if not user_id or not username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    try:
        user_id_int = int(user_id)
    except (ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    user = get_user_by_id(user_id_int)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    # Ensure username in token matches the current database username (defense-in-depth)
    if user["username"] != username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    return user


# ------------------------------------------------------------------------------
# FastAPI App and Exception Handlers
# ------------------------------------------------------------------------------

app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")


@app.on_event("startup")
def on_startup() -> None:
    try:
        init_db()
    except Exception:
        # If DB init fails, app should still run but endpoints will return 500 when accessed.
        print("ERROR: Failed to initialize the database.")


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Conform to schema where 401 and 400 use {"message": "..."}
    if exc.status_code == 401:
        msg = exc.detail if isinstance(exc.detail, str) else "Invalid authentication token"
        return JSONResponse(status_code=401, content={"message": msg})
    if exc.status_code == 400:
        msg = exc.detail if isinstance(exc.detail, str) else "Bad Request"
        return JSONResponse(status_code=400, content={"message": msg})
    # For others, return standard detail to not mask meanings
    detail = exc.detail if exc.detail is not None else "Error"
    return JSONResponse(status_code=exc.status_code, content={"detail": detail})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Avoid leaking internal details (CWE-703)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@app.post("/register", summary="User registration", tags=["Authentication"])
def register(payload: RegisterRequest):
    email = payload.email.strip().lower()
    username = payload.username.strip()
    # Enforce lower-case usernames to avoid impersonation by case differences
    # Alternatively, to preserve case, comment the next line
    username = username.lower()

    # Extra validation defense-in-depth (already enforced by pydantic pattern)
    if not re.fullmatch(USERNAME_REGEX, username):
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

    if len(payload.password) < 8:
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

    password_hash = hash_password(payload.password)
    try:
        user_id = create_user(email=email, username=username, password_hash=password_hash)
    except sqlite3.IntegrityError:
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    except Exception:
        # Unexpected DB errors
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

    return JSONResponse(status_code=201, content={"message": "Registration successful"})


@app.post("/login", summary="User login", tags=["Authentication"])
def login(payload: LoginRequest):
    email = payload.email.strip().lower()
    try:
        user = get_user_by_email(email)
    except Exception:
        # Avoid leaking specific error info
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

    if not user:
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

    if not verify_password(payload.password, user["password_hash"]):
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

    token = create_access_token(user_id=user["id"], username=user["username"])
    return {"token": token, "message": "Login successful"}


@app.post("/set_secret", summary="Set secret")
def set_secret(data: SetSecretRequest, current_user: sqlite3.Row = Depends(get_current_user)):
    # Ensure user can only set their own secret
    requested_username = data.username.strip().lower()
    if requested_username != current_user["username"]:
        # Do not disclose existence of other users; treat as auth issue
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    try:
        upsert_secret(user_id=current_user["id"], secret=data.secret)
    except Exception:
        # Handle rare DB failure scenarios
        raise HTTPException(status_code=500, detail="Internal server error")

    return {"message": "Secret has been set successfully"}


@app.get("/get_secret", summary="Get secret")
def get_secret(username: str = Query(..., min_length=3, max_length=30), current_user: sqlite3.Row = Depends(get_current_user)):
    requested_username = username.strip().lower()
    if not re.fullmatch(USERNAME_REGEX, requested_username):
        # Validation failure, but respond generically to not leak details
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    if requested_username != current_user["username"]:
        # Prevent access to others' secrets
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    try:
        secret_value = get_secret_by_user_id(current_user["id"])
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")

    if secret_value is None:
        # If no secret has been set, return an empty string to match type expectation
        secret_value = ""

    return {"secret": secret_value}


# ------------------------------------------------------------------------------
# Run Server
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=5000, reload=False, access_log=True)