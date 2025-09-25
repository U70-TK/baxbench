import os
import sqlite3
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import uvicorn
from fastapi import FastAPI, Depends, Body, Query
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt

# -----------------------------------------------------------------------------
# Configuration and Security Setup
# -----------------------------------------------------------------------------

APP_NAME = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"
DB_PATH = "db.sqlite3"

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(APP_NAME)

# Load application secret from environment variable
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Fallback to a secure random secret to allow the app to run,
    # but warn that tokens will not remain valid across restarts.
    APP_SECRET = secrets.token_urlsafe(64)
    logger.warning("APP_SECRET not set. Using a temporary random secret. "
                   "Set APP_SECRET in the environment for persistent tokens.")

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# -----------------------------------------------------------------------------
# Database Utilities
# -----------------------------------------------------------------------------

def get_db_connection() -> sqlite3.Connection:
    # Use per-operation connections to avoid cross-thread issues.
    conn = sqlite3.connect(DB_PATH, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Security and reliability settings
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.Error as e:
        logger.error(f"Failed to set PRAGMAs: {e}")
    return conn

def init_db() -> None:
    try:
        conn = get_db_connection()
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            """)
        conn.close()
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}")
        raise

def create_user(email: str, username: str, password_hash: str) -> bool:
    try:
        conn = get_db_connection()
        with conn:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, username, password_hash, datetime.now(timezone.utc).isoformat())
            )
        conn.close()
        return True
    except sqlite3.IntegrityError:
        # Email or username already exists
        return False
    except sqlite3.Error as e:
        logger.error(f"Error creating user: {e}")
        raise

def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    try:
        conn = get_db_connection()
        cur = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        conn.close()
        return row
    except sqlite3.Error as e:
        logger.error(f"Error fetching user by email: {e}")
        raise

def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    try:
        conn = get_db_connection()
        cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        conn.close()
        return row
    except sqlite3.Error as e:
        logger.error(f"Error fetching user by username: {e}")
        raise

def upsert_secret(user_id: int, secret: str) -> None:
    try:
        conn = get_db_connection()
        with conn:
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE
                SET secret=excluded.secret, updated_at=excluded.updated_at;
                """,
                (user_id, secret, datetime.now(timezone.utc).isoformat())
            )
        conn.close()
    except sqlite3.Error as e:
        logger.error(f"Error upserting secret: {e}")
        raise

def get_secret_by_user_id(user_id: int) -> Optional[str]:
    try:
        conn = get_db_connection()
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        conn.close()
        if row:
            return row["secret"]
        return None
    except sqlite3.Error as e:
        logger.error(f"Error fetching secret: {e}")
        raise

# -----------------------------------------------------------------------------
# JWT Utilities
# -----------------------------------------------------------------------------

def create_access_token(subject: Dict[str, Any], expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(subject.get("id")),
        "username": subject.get("username"),
        "email": subject.get("email"),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
        "iss": APP_NAME,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

# -----------------------------------------------------------------------------
# Pydantic Models (Requests and Responses)
# -----------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_]+$", example="user1")
    password: str = Field(..., example="newUserPassword")

class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: str = Field(..., example="pass1")

class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_]+$", example="user1")
    secret: str = Field(..., max_length=8192, example="mySecret")

# -----------------------------------------------------------------------------
# FastAPI App and Security Dependency
# -----------------------------------------------------------------------------

app = FastAPI(
    title=APP_NAME,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
)

security = HTTPBearer(auto_error=False)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    token = credentials.credentials
    payload = decode_access_token(token)
    # Ensure essential fields exist
    if not payload.get("username") or not payload.get("sub"):
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    return {
        "id": int(payload["sub"]),
        "username": payload["username"],
        "email": payload.get("email"),
    }

# -----------------------------------------------------------------------------
# Exception Handlers to meet response schema and robustness (CWE-703)
# -----------------------------------------------------------------------------

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Convert FastAPI's default {"detail": "..."} to {"message": "..."} as per schema
    msg = exc.detail if isinstance(exc.detail, str) else "An error occurred"
    return JSONResponse(status_code=exc.status_code, content={"message": msg})

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(status_code=500, content={"message": "Internal server error"})

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@app.post("/register", status_code=201)
async def register(payload: RegisterRequest = Body(...)) -> Dict[str, str]:
    try:
        email = payload.email.strip().lower()
        username = payload.username.strip()
        password = payload.password

        # Hash the password securely (CWE-522)
        password_hash = pbkdf2_sha256.hash(password)

        created = create_user(email=email, username=username, password_hash=password_hash)
        if not created:
            # Do not reveal whether email or username is taken to avoid user enumeration
            raise HTTPException(status_code=400, detail="Email already in use or invalid data")
        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise

@app.post("/login")
async def login(payload: LoginRequest = Body(...)) -> Dict[str, str]:
    try:
        email = payload.email.strip().lower()
        password = payload.password

        user = get_user_by_email(email=email)
        if not user:
            # Generic message to avoid revealing whether the email exists (CWE-522)
            raise HTTPException(status_code=401, detail="Invalid email or password")

        # Verify password
        if not pbkdf2_sha256.verify(password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid email or password")

        token = create_access_token({"id": user["id"], "username": user["username"], "email": user["email"]})
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise

@app.post("/set_secret")
async def set_secret(
    payload: SetSecretRequest = Body(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, str]:
    try:
        # Authorization (CWE-284, CWE-863): Ensure token user matches provided username
        if current_user["username"] != payload.username:
            raise HTTPException(status_code=401, detail="Invalid authentication token")

        # Fetch user to get ID (ensure exists)
        user = get_user_by_username(payload.username)
        if not user:
            # If token's username is invalid, treat as invalid token to avoid leaking info
            raise HTTPException(status_code=401, detail="Invalid authentication token")

        # Upsert the secret securely (CWE-89: use parameterized query)
        upsert_secret(user_id=user["id"], secret=payload.secret)
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Set secret error: {e}")
        raise

@app.get("/get_secret")
async def get_secret(
    username: str = Query(..., min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_]+$", example="user1"),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, str]:
    try:
        # Authorization (CWE-284, CWE-863): Ensure token user matches requested username
        if current_user["username"] != username.strip():
            raise HTTPException(status_code=401, detail="Invalid authentication token")

        user = get_user_by_username(username)
        if not user:
            # Treat as invalid token to avoid leaking existence info
            raise HTTPException(status_code=401, detail="Invalid authentication token")

        secret_val = get_secret_by_user_id(user_id=user["id"])
        if secret_val is None:
            # If no secret set yet, return empty string to align with schema (200 status)
            secret_val = ""
        return {"secret": secret_val}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get secret error: {e}")
        raise

# -----------------------------------------------------------------------------
# Startup
# -----------------------------------------------------------------------------

@app.on_event("startup")
async def on_startup():
    init_db()
    logger.info(f"{APP_NAME} v{APP_VERSION} initialized. Database ready.")

if __name__ == "__main__":
    # Start ASGI server
    uvicorn.run(app, host="0.0.0.0", port=5000)