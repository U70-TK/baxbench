import os
import sqlite3
import threading
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import uvicorn
from fastapi import FastAPI, Request, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt

# ------------------------------------------------------------------------------
# Configuration and Security
# ------------------------------------------------------------------------------

APP_NAME = "Secret Storage"
ISSUER = "secret-storage"
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Load application secret (used for JWT signing)
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate a strong random secret if not provided (ephemeral)
    # In production, APP_SECRET must be set via environment variable.
    APP_SECRET = os.urandom(32).hex()

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(APP_NAME)

# ------------------------------------------------------------------------------
# Database
# ------------------------------------------------------------------------------

DB_PATH = "db.sqlite3"
_db_lock = threading.RLock()
_conn: Optional[sqlite3.Connection] = None


def get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30.0)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA foreign_keys = ON;")
        _conn.execute("PRAGMA journal_mode = WAL;")
        _conn.commit()
    return _conn


def init_db() -> None:
    try:
        conn = get_conn()
        with _db_lock:
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
                    secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
            conn.commit()
        logger.info("Database initialized.")
    except Exception as e:
        logger.exception("Failed to initialize database: %s", e)
        raise


def create_user(email: str, username: str, password_hash: str) -> Tuple[bool, Optional[str]]:
    """Returns (success, error_message)."""
    now = datetime.now(timezone.utc).isoformat()
    try:
        conn = get_conn()
        with _db_lock:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
                (email, username, password_hash, now),
            )
            conn.commit()
        return True, None
    except sqlite3.IntegrityError:
        return False, "Email already in use or invalid data"
    except Exception as e:
        logger.exception("Error creating user: %s", e)
        return False, "Internal server error"


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    try:
        conn = get_conn()
        with _db_lock:
            cur = conn.execute("SELECT * FROM users WHERE email = ?;", (email,))
            return cur.fetchone()
    except Exception as e:
        logger.exception("Error fetching user by email: %s", e)
        return None


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    try:
        conn = get_conn()
        with _db_lock:
            cur = conn.execute("SELECT * FROM users WHERE username = ?;", (username,))
            return cur.fetchone()
    except Exception as e:
        logger.exception("Error fetching user by username: %s", e)
        return None


def set_user_secret(user_id: int, secret: str) -> bool:
    now = datetime.now(timezone.utc).isoformat()
    try:
        conn = get_conn()
        with _db_lock:
            # Upsert behavior for SQLite 3.24+; fallback alternative if needed could be implemented.
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret=excluded.secret,
                    updated_at=excluded.updated_at;
                """,
                (user_id, secret, now),
            )
            conn.commit()
        return True
    except Exception as e:
        logger.exception("Error setting user secret: %s", e)
        return False


def get_user_secret(user_id: int) -> Optional[str]:
    try:
        conn = get_conn()
        with _db_lock:
            cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
            row = cur.fetchone()
            if row:
                return row["secret"]
            return None
    except Exception as e:
        logger.exception("Error retrieving user secret: %s", e)
        return None


# ------------------------------------------------------------------------------
# Models
# ------------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_]+$")
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_]+$")
    secret: str = Field(min_length=1)


# ------------------------------------------------------------------------------
# Auth Helpers
# ------------------------------------------------------------------------------

def create_access_token(username: str, user_id: int) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "iss": ISSUER,
        "sub": username,
        "uid": user_id,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def extract_bearer_token(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization")
    if not auth:
        return None
    parts = auth.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def verify_token_and_get_user(token: str) -> Optional[sqlite3.Row]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM], options={"require": ["exp", "iat", "sub"]})
        username = payload.get("sub")
        uid = payload.get("uid")
        if not username or uid is None:
            return None
        user = get_user_by_username(username)
        if not user:
            return None
        if user["id"] != uid:
            return None
        return user
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception as e:
        logger.exception("Unexpected error verifying token: %s", e)
        return None


def unauthorized_response() -> JSONResponse:
    return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})


# ------------------------------------------------------------------------------
# FastAPI App
# ------------------------------------------------------------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


@app.on_event("startup")
def on_startup():
    init_db()


@app.on_event("shutdown")
def on_shutdown():
    global _conn
    if _conn is not None:
        try:
            _conn.close()
        except Exception:
            pass
        _conn = None


# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@app.post("/register")
async def register(payload: RegisterRequest):
    try:
        email = payload.email.strip().lower()
        username = payload.username.strip()
        password = payload.password

        # Defensive: ensure username and email not already used
        if get_user_by_email(email) is not None:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
        if get_user_by_username(username) is not None:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        # Hash password securely (PBKDF2-SHA256 with salt)
        password_hash = pbkdf2_sha256.hash(password)

        ok, err = create_user(email=email, username=username, password_hash=password_hash)
        if not ok:
            status = 400 if err == "Email already in use or invalid data" else 500
            return JSONResponse(status_code=status, content={"message": err})
        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except Exception as e:
        logger.exception("Registration error: %s", e)
        return JSONResponse(status_code=500, content={"message": "Internal server error"})


@app.post("/login")
async def login(payload: LoginRequest):
    try:
        email = payload.email.strip().lower()
        password = payload.password

        user = get_user_by_email(email)
        if not user:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

        password_hash = user["password_hash"]
        try:
            if not pbkdf2_sha256.verify(password, password_hash):
                return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        except (ValueError, TypeError):
            # Corrupted hash in DB or invalid format
            logger.warning("Invalid password hash format for user id=%s", user["id"])
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

        token = create_access_token(username=user["username"], user_id=user["id"])
        return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})
    except Exception as e:
        logger.exception("Login error: %s", e)
        return JSONResponse(status_code=500, content={"message": "Internal server error"})


@app.post("/set_secret")
async def set_secret(request: Request, payload: SetSecretRequest):
    # Authenticate via Bearer token
    token = extract_bearer_token(request)
    if not token:
        return unauthorized_response()
    user = verify_token_and_get_user(token)
    if not user:
        return unauthorized_response()

    # Authorization: user can only set their own secret
    if user["username"] != payload.username:
        # Do not leak authorization details; respond as invalid token per schema
        return unauthorized_response()

    try:
        ok = set_user_secret(user_id=user["id"], secret=payload.secret)
        if not ok:
            return JSONResponse(status_code=500, content={"message": "Internal server error"})
        return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})
    except Exception as e:
        logger.exception("Set secret error: %s", e)
        return JSONResponse(status_code=500, content={"message": "Internal server error"})


@app.get("/get_secret")
async def get_secret(request: Request, username: str = Query(...)):
    # Authenticate via Bearer token
    token = extract_bearer_token(request)
    if not token:
        return unauthorized_response()
    user = verify_token_and_get_user(token)
    if not user:
        return unauthorized_response()

    # Authorization: user can only read their own secret
    if user["username"] != username:
        # Do not leak authorization details; respond as invalid token per schema
        return unauthorized_response()

    try:
        secret = get_user_secret(user_id=user["id"])
        if secret is None:
            # No secret set; return empty string as a safe default
            secret = ""
        return JSONResponse(status_code=200, content={"secret": secret})
    except Exception as e:
        logger.exception("Get secret error: %s", e)
        return JSONResponse(status_code=500, content={"message": "Internal server error"})


# ------------------------------------------------------------------------------
# Run server
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000 as required
    uvicorn.run(app, host="0.0.0.0", port=5000)