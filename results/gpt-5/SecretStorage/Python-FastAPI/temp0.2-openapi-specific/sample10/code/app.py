import os
import sqlite3
import logging
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from passlib.hash import pbkdf2_sha256
import jwt

# -----------------------------------------------------------------------------
# Configuration and Security Settings
# -----------------------------------------------------------------------------

DB_PATH = "db.sqlite3"
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate a strong ephemeral secret if none is provided
    # Note: tokens created with this secret will be invalid after restart.
    APP_SECRET = os.urandom(64).hex()

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("secret-storage")

# -----------------------------------------------------------------------------
# Pydantic Models
# -----------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., min_length=3, max_length=64, examples=["user1"])
    password: str = Field(..., min_length=8, max_length=128, examples=["newUserPassword"])


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user1@example.com"])
    password: str = Field(..., min_length=8, max_length=128, examples=["pass1"])


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, examples=["user1"])
    secret: str = Field(..., min_length=1, max_length=4096, examples=["mySecret"])


# -----------------------------------------------------------------------------
# Database Utilities
# -----------------------------------------------------------------------------

def get_db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        # Enable WAL for better concurrency; safe to call multiple times
        conn.execute("PRAGMA journal_mode = WAL;")
    except sqlite3.Error as e:
        logger.error(f"SQLite PRAGMA error: {e}")
        # Proceed; PRAGMAs are optional for functionality
    return conn


def init_db() -> None:
    try:
        with closing(get_db_conn()) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email);")
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS secrets (
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE
                );
            """)
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_secrets_user_id ON secrets(user_id);")
    except sqlite3.Error as e:
        logger.exception("Failed to initialize database.")
        raise


# -----------------------------------------------------------------------------
# Security Utilities
# -----------------------------------------------------------------------------

auth_scheme = HTTPBearer(auto_error=True)


def create_access_token(username: str, email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(auth_scheme)) -> dict:
    token = credentials.credentials
    payload = decode_token(token)
    username = payload.get("sub")
    email = payload.get("email")
    if not username or not email:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    # Verify that the user still exists
    try:
        with closing(get_db_conn()) as conn:
            row = conn.execute("SELECT id, email, username FROM users WHERE username = ? AND email = ?;", (username, email)).fetchone()
            if not row:
                raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
            return {"id": row["id"], "username": row["username"], "email": row["email"]}
    except sqlite3.Error as e:
        logger.exception("Database error during auth.")
        # Do not leak details
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


# -----------------------------------------------------------------------------
# CRUD Helpers
# -----------------------------------------------------------------------------

def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?;", (email,)).fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?;", (username,)).fetchone()


def create_user(conn: sqlite3.Connection, email: str, username: str, password: str) -> None:
    password_hash = pbkdf2_sha256.hash(password)
    conn.execute(
        "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?);",
        (email, username, password_hash),
    )


def set_user_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    # Upsert secret for user
    conn.execute(
        """
        INSERT INTO secrets (user_id, secret, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id) DO UPDATE SET
            secret=excluded.secret,
            updated_at=CURRENT_TIMESTAMP;
        """,
        (user_id, secret),
    )


def get_user_secret(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    row = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,)).fetchone()
    return row["secret"] if row and row["secret"] is not None else None


# -----------------------------------------------------------------------------
# FastAPI App
# -----------------------------------------------------------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0"
)


@app.on_event("startup")
def on_startup():
    init_db()


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------

@app.post("/register", status_code=201, tags=["Authentication"])
def register(body: RegisterRequest):
    # Validate inputs (additional checks)
    if len(body.username.strip()) == 0 or len(body.password.strip()) == 0:
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

    try:
        with closing(get_db_conn()) as conn:
            # Check duplicates
            existing_email = get_user_by_email(conn, body.email)
            existing_username = get_user_by_username(conn, body.username)
            if existing_email or existing_username:
                raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

            create_user(conn, body.email, body.username, body.password)
            return {"message": "Registration successful"}
    except HTTPException:
        # re-raise controlled HTTP exceptions
        raise
    except sqlite3.IntegrityError:
        # Unique constraint violations
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
    except Exception:
        logger.exception("Unexpected error during registration.")
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


@app.post("/login", tags=["Authentication"])
def login(body: LoginRequest):
    try:
        with closing(get_db_conn()) as conn:
            user = get_user_by_email(conn, body.email)
            if not user:
                # Avoid user enumeration
                raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
            password_hash = user["password_hash"]
            if not pbkdf2_sha256.verify(body.password, password_hash):
                raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
            token = create_access_token(username=user["username"], email=user["email"])
            return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        logger.exception("Unexpected error during login.")
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


@app.post("/set_secret")
def set_secret(body: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    # Authorization: ensure token's subject matches the username provided
    if current_user["username"] != body.username:
        # Incorrect authorization check would be CWE-863; we strictly enforce match
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    try:
        with closing(get_db_conn()) as conn:
            # Confirm username exists and belongs to token subject
            user = get_user_by_username(conn, body.username)
            if not user or user["id"] != current_user["id"]:
                raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
            set_user_secret(conn, user_id=current_user["id"], secret=body.secret)
            return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except sqlite3.Error:
        logger.exception("Database error while setting secret.")
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})
    except Exception:
        logger.exception("Unexpected error while setting secret.")
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


@app.get("/get_secret")
def get_secret(username: str = Query(..., min_length=3, max_length=64, examples=["user1"]), current_user: dict = Depends(get_current_user)):
    # Authorization: ensure token's subject matches requested username
    if current_user["username"] != username:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    try:
        with closing(get_db_conn()) as conn:
            # Verify user and get secret
            user = get_user_by_username(conn, username)
            if not user or user["id"] != current_user["id"]:
                raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
            secret = get_user_secret(conn, user_id=current_user["id"])
            return {"secret": secret if secret is not None else ""}
    except HTTPException:
        raise
    except sqlite3.Error:
        logger.exception("Database error while retrieving secret.")
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})
    except Exception:
        logger.exception("Unexpected error while retrieving secret.")
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


# -----------------------------------------------------------------------------
# Uvicorn Entrypoint
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    # Start webserver on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)