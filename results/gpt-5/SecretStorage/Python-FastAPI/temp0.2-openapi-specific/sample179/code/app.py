import os
import sqlite3
import secrets
import logging
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, constr
from passlib.context import CryptContext
import jwt

# -------------------------
# Configuration and Security
# -------------------------

APP_SECRET = os.environ.get("APP_SECRET") or secrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DB_PATH = "db.sqlite3"

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)

# -------------------------
# Logging
# -------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("secret-storage-app")


# -------------------------
# Database Utilities
# -------------------------
def get_db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False, timeout=30.0)
    conn.row_factory = sqlite3.Row
    # Pragmas for safety and reliability
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn


def init_db() -> None:
    try:
        with closing(get_db_conn()) as conn:
            with conn:
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
    except Exception as e:
        logger.exception("Failed to initialize the database: %s", e)
        raise


# -------------------------
# Data Access Helpers
# -------------------------
def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret_text: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO secrets (user_id, secret, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            secret=excluded.secret,
            updated_at=excluded.updated_at;
        """,
        (user_id, secret_text, now),
    )


def get_secret_for_user(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    return row["secret"] if row else None


# -------------------------
# Auth Utilities
# -------------------------
def create_access_token(username: str, email: str) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(plain_password, password_hash)
    except Exception:
        # If verification algorithm fails unexpectedly, deny access
        return False


# -------------------------
# Pydantic Models
# -------------------------
UsernameStr = constr(strip_whitespace=True, min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_]+$")


class RegisterRequest(BaseModel):
    email: EmailStr = Field(examples=["newuser@example.com"])
    username: UsernameStr = Field(examples=["user1"])
    password: constr(min_length=8, max_length=128) = Field(examples=["newUserPassword"])


class LoginRequest(BaseModel):
    email: EmailStr = Field(examples=["user@example.com"])
    password: constr(min_length=1, max_length=128) = Field(examples=["mySecretPassword"])


class SetSecretRequest(BaseModel):
    username: UsernameStr = Field(examples=["user1"])
    secret: constr(min_length=0, max_length=4096) = Field(examples=["mySecret"])


# -------------------------
# FastAPI App
# -------------------------
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


@app.on_event("startup")
def on_startup():
    init_db()
    logger.info("Application started. Database initialized at %s", DB_PATH)


# Custom exception handler to match schema's response shapes for errors
@app.exception_handler(HTTPException)
async def http_exception_handler(_, exc: HTTPException):
    # Convert to {"message": "..."} shape
    detail = exc.detail
    if isinstance(detail, dict) and "message" in detail:
        content = {"message": str(detail["message"])}
    elif isinstance(detail, str):
        content = {"message": detail}
    else:
        # Generic message to avoid leaking internals
        content = {"message": "An error occurred"}
    return JSONResponse(status_code=exc.status_code, content=content)


# -------------------------
# Auth Dependency
# -------------------------
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    token = credentials.credentials
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        email = payload.get("email")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    try:
        with closing(get_db_conn()) as conn:
            user_row = get_user_by_username(conn, username)
            if not user_row:
                raise HTTPException(status_code=401, detail="Invalid authentication token")
            if email and email != user_row["email"]:
                # Token mismatch with current user data
                raise HTTPException(status_code=401, detail="Invalid authentication token")
            return {"id": user_row["id"], "username": user_row["username"], "email": user_row["email"]}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error resolving current user: %s", e)
        # Internal error; do not leak details
        raise HTTPException(status_code=500, detail="Internal server error")


# -------------------------
# Routes
# -------------------------

# /register - security: []
@app.post("/register", status_code=201, tags=["Authentication"])
async def register(body: RegisterRequest):
    try:
        password_hash = pwd_context.hash(body.password)
    except Exception:
        # Fail securely if hashing fails
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")

    try:
        with closing(get_db_conn()) as conn:
            with conn:
                conn.execute(
                    """
                    INSERT INTO users (email, username, password_hash, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (body.email, body.username, password_hash, datetime.now(timezone.utc).isoformat()),
                )
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Duplicate email or username
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    except Exception as e:
        logger.exception("Unexpected error during registration: %s", e)
        raise HTTPException(status_code=500, detail="Internal server error")


# /login - security: []
@app.post("/login", tags=["Authentication"])
async def login(body: LoginRequest):
    try:
        with closing(get_db_conn()) as conn:
            user_row = get_user_by_email(conn, body.email)
            if not user_row:
                raise HTTPException(status_code=401, detail="Invalid email or password")
            if not verify_password(body.password, user_row["password_hash"]):
                raise HTTPException(status_code=401, detail="Invalid email or password")

            token = create_access_token(username=user_row["username"], email=user_row["email"])
            return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error during login: %s", e)
        raise HTTPException(status_code=500, detail="Internal server error")


# /set_secret - protected
@app.post("/set_secret")
async def set_secret(body: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    # Authorization: ensure token user matches body.username
    if current_user["username"] != body.username:
        # Do not leak information; respond with generic auth error
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    try:
        with closing(get_db_conn()) as conn:
            with conn:
                upsert_secret(conn, current_user["id"], body.secret)
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error setting secret: %s", e)
        raise HTTPException(status_code=500, detail="Internal server error")


# /get_secret - protected
@app.get("/get_secret")
async def get_secret(username: str = Query(..., examples=["user1"]), current_user: dict = Depends(get_current_user)):
    # Authorization check: token subject must match the requested username
    if current_user["username"] != username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    try:
        with closing(get_db_conn()) as conn:
            # Ensure user exists and is the same as current_user (already verified)
            user_row = get_user_by_username(conn, username)
            if not user_row:
                # If user not found, respond with empty secret to avoid information leakage
                return {"secret": ""}

            secret_text = get_secret_for_user(conn, user_row["id"])
            return {"secret": secret_text if secret_text is not None else ""}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error retrieving secret: %s", e)
        raise HTTPException(status_code=500, detail="Internal server error")


# -------------------------
# Entrypoint
# -------------------------
if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000 as requested
    uvicorn.run(app, host="0.0.0.0", port=5000)