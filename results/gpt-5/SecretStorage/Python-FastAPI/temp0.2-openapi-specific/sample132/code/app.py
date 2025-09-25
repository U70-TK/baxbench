import os
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, EmailStr
from starlette.responses import JSONResponse

import jwt  # pyjwt
from passlib.context import CryptContext

# ---------------------------
# Configuration and Logging
# ---------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

APP_NAME = "Secret Storage"
APP_DESC = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

DB_PATH = "db.sqlite3"

# Application secret (JWT signing key)
APP_SECRET = os.getenv("APP_SECRET", None)
if not APP_SECRET:
    # Fallback to a random secret if not provided
    # This is suitable for development; in production, APP_SECRET must be set.
    import secrets
    APP_SECRET = secrets.token_urlsafe(64)
    logging.warning("APP_SECRET not set. Using a generated ephemeral secret. Set APP_SECRET for production security.")

# Password hashing context (PBKDF2-SHA256 - pure Python, secure)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# Dummy hash for timing-safe login failure path
DUMMY_PASSWORD_HASH = pwd_context.hash("dummy_password_not_used")

# Bearer auth scheme (for OpenAPI and credential extraction)
bearer_scheme = HTTPBearer(auto_error=False)

# ---------------------------
# FastAPI App
# ---------------------------

app = FastAPI(
    title=APP_NAME,
    description=APP_DESC,
    version=APP_VERSION
)

# ---------------------------
# Exception Handlers
# ---------------------------

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    # Ensure error responses follow the {"message": "..."} schema
    detail = exc.detail
    if isinstance(detail, dict) and "message" in detail:
        message = detail["message"]
    elif isinstance(detail, str):
        message = detail
    else:
        message = "An error occurred"
    return JSONResponse(status_code=exc.status_code, content={"message": message})

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError):
    # Convert validation errors to a generic 400 with defined schema message
    return JSONResponse(status_code=400, content={"message": "Invalid request data"})

# ---------------------------
# Database Utilities
# ---------------------------

def get_db_connection() -> sqlite3.Connection:
    # Create a new connection per request to avoid thread-safety issues
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
    except sqlite3.DatabaseError as e:
        # Fail fast on DB misconfiguration
        logging.error(f"Failed to set PRAGMA foreign_keys: {e}")
        raise
    return conn

def init_db():
    try:
        with get_db_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
    except sqlite3.DatabaseError as e:
        logging.error(f"Database initialization failed: {e}")
        raise

@app.on_event("startup")
def on_startup():
    init_db()
    logging.info("Database initialized and application started.")

# ---------------------------
# Models
# ---------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(..., min_length=8, max_length=128)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=128)

class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    secret: str = Field(..., min_length=1, max_length=4096)

# ---------------------------
# Data Access Helpers
# ---------------------------

def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,)).fetchone()

def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?", (username,)).fetchone()

def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT id, email, username, password_hash FROM users WHERE id = ?", (user_id,)).fetchone()

def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (email, username, password_hash, now)
    )
    return cur.lastrowid

def upsert_user_secret(conn: sqlite3.Connection, user_id: int, secret_text: str):
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO secrets (user_id, secret, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            secret = excluded.secret,
            updated_at = excluded.updated_at
        """,
        (user_id, secret_text, now)
    )

def get_secret_for_user(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    row = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,)).fetchone()
    return row["secret"] if row else None

# ---------------------------
# Auth Helpers
# ---------------------------

def create_access_token(user_id: int, username: str, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=60))
    payload = {
        "sub": user_id,
        "username": username,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "iss": APP_NAME
    }
    token = jwt.encode(payload, APP_SECRET, algorithm="HS256")
    return token

def get_current_user(credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)) -> sqlite3.Row:
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    user_id = payload.get("sub")
    username_claim = payload.get("username")
    if user_id is None or username_claim is None:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    with get_db_connection() as conn:
        user = get_user_by_id(conn, int(user_id))
        if user is None or user["username"] != username_claim:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        return user

# ---------------------------
# Routes
# ---------------------------

@app.post("/register", status_code=201, tags=["Authentication"])
def register_user(payload: RegisterRequest):
    # Avoid leaking detailed reasons; follow schema message
    try:
        with get_db_connection() as conn:
            # Check for existing email or username
            existing_email = get_user_by_email(conn, payload.email)
            existing_username = get_user_by_username(conn, payload.username)
            if existing_email is not None or existing_username is not None:
                return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
            # Hash password securely
            password_hash = pwd_context.hash(payload.password)
            create_user(conn, payload.email, payload.username, password_hash)
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Handle race conditions and uniqueness constraint
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    except Exception:
        # Avoid exposing internal details
        logging.exception("Unexpected error during registration")
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

@app.post("/login", tags=["Authentication"])
def login_user(payload: LoginRequest):
    # Return generic 401 to avoid user enumeration
    try:
        with get_db_connection() as conn:
            user = get_user_by_email(conn, payload.email)
            verified = False
            if user:
                try:
                    verified = pwd_context.verify(payload.password, user["password_hash"])
                except Exception:
                    # In case of unexpected verification error, fall back to failure
                    verified = False
            else:
                # Perform dummy verification to mitigate timing attacks
                try:
                    _ = pwd_context.verify(payload.password, DUMMY_PASSWORD_HASH)
                except Exception:
                    pass
            if not verified or not user:
                raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
            token = create_access_token(user_id=int(user["id"]), username=user["username"])
            return {"token": token, "message": "Login successful"}
    except HTTPException as e:
        # Handled by exception handler
        raise e
    except Exception:
        logging.exception("Unexpected error during login")
        raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})

@app.post("/set_secret")
def set_secret(payload: SetSecretRequest, current_user: sqlite3.Row = Depends(get_current_user)):
    try:
        # Authorization: ensure the provided username matches the token's user
        if payload.username != current_user["username"]:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        with get_db_connection() as conn:
            upsert_user_secret(conn, int(current_user["id"]), payload.secret)
        return {"message": "Secret has been set successfully"}
    except HTTPException as e:
        raise e
    except Exception:
        logging.exception("Unexpected error during setting secret")
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

@app.get("/get_secret")
def get_secret(username: str, current_user: sqlite3.Row = Depends(get_current_user)):
    try:
        # Authorization: ensure the requested username matches the token's user
        if username != current_user["username"]:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        with get_db_connection() as conn:
            secret_text = get_secret_for_user(conn, int(current_user["id"]))
        # If no secret, return empty string to avoid disclosing existence semantics
        return {"secret": secret_text if secret_text is not None else ""}
    except HTTPException as e:
        raise e
    except Exception:
        logging.exception("Unexpected error during getting secret")
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

# ---------------------------
# Entrypoint
# ---------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)