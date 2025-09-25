import os
import sqlite3
import secrets as py_secrets
from datetime import datetime, timedelta
from typing import Optional

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, ValidationError
from passlib.context import CryptContext
import jwt

# Application configuration
APP_NAME = "Secret Storage"
APP_DESC = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"
DB_PATH = "db.sqlite3"
JWT_ALGORITHM = "HS256"
JWT_ISSUER = "secret-storage"
DEFAULT_TOKEN_EXPIRE_MINUTES = 60

# Obtain application secret
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Generate a secure random secret if not provided
    # Note: In production, always provide a strong static secret via environment variable.
    APP_SECRET = py_secrets.token_urlsafe(64)

# Password hashing context using PBKDF2-SHA256 (no external deps)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# Security scheme
bearer_scheme = HTTPBearer(auto_error=False)

# FastAPI app
app = FastAPI(
    title=APP_NAME,
    description=APP_DESC,
    version=APP_VERSION,
)


# ---------------------------
# Database Utilities
# ---------------------------

def get_db_connection() -> sqlite3.Connection:
    """
    Create a new SQLite connection per request.
    - Enables foreign key constraints.
    - Uses row factory for dict-like access if needed.
    """
    conn = sqlite3.connect(DB_PATH)
    # Ensure string handling is safe
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """
    Initialize database with required tables.
    """
    conn = get_db_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER PRIMARY KEY,
                secret TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        conn.commit()
    except Exception:
        # Even on initialization, catch and ignore to avoid crash; actual errors will surface on use
        pass
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# ---------------------------
# Models
# ---------------------------

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., min_length=3, max_length=64, example="user1", pattern=r"^[A-Za-z0-9_\.]+$")
    password: str = Field(..., min_length=8, max_length=128, example="newUserPassword")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user@example.com")
    password: str = Field(..., min_length=8, max_length=128, example="mySecretPassword")


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, example="user1", pattern=r"^[A-Za-z0-9_\.]+$")
    secret: str = Field(..., min_length=1, max_length=4096, example="mySecret")


# ---------------------------
# JWT Utilities
# ---------------------------

def create_access_token(*, username: str, email: str, user_id: int, expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=DEFAULT_TOKEN_EXPIRE_MINUTES))
    payload = {
        "sub": username,
        "uid": user_id,
        "email": email,
        "iss": JWT_ISSUER,
        "iat": int(datetime.utcnow().timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_access_token(token: str) -> dict:
    try:
        decoded = jwt.decode(
            token,
            APP_SECRET,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            options={"require": ["exp", "iat", "iss", "sub"]}
        )
        return decoded
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})


# Dependency to extract and validate token
def get_current_token_payload(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    if credentials is None or not credentials.scheme.lower() == "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    return decode_access_token(token)


# ---------------------------
# Helper Functions
# ---------------------------

def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[dict]:
    cur = conn.cursor()
    cur.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    if row:
        return {"id": row[0], "email": row[1], "username": row[2], "password_hash": row[3]}
    return None


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[dict]:
    cur = conn.cursor()
    cur.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if row:
        return {"id": row[0], "email": row[1], "username": row[2], "password_hash": row[3]}
    return None


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret_text: str):
    """
    Insert or update a secret securely using parameterized queries.
    """
    cur = conn.cursor()
    # First check if secret exists
    cur.execute("SELECT user_id FROM secrets WHERE user_id = ?", (user_id,))
    if cur.fetchone():
        cur.execute("UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?", (secret_text, datetime.utcnow().isoformat(), user_id))
    else:
        cur.execute(
            "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
            (user_id, secret_text, datetime.utcnow().isoformat())
        )
    conn.commit()


def get_secret_by_user_id(conn: sqlite3.Connection, user_id: int) -> str:
    cur = conn.cursor()
    cur.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if row and row[0] is not None:
        return row[0]
    return ""


# ---------------------------
# Exception Handlers
# ---------------------------

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Generic catch-all to prevent leaking internal details (CWE-703)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "Internal server error"}
    )


# ---------------------------
# Endpoints
# ---------------------------

@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(payload: RegisterRequest):
    """
    Register a new user with email, username and password.
    """
    conn = get_db_connection()
    try:
        # Normalize email and username
        email = payload.email.strip().lower()
        username = payload.username.strip()

        # Check for existing email or username
        existing_email = get_user_by_email(conn, email)
        existing_username = get_user_by_username(conn, username)
        if existing_email or existing_username:
            # Do not reveal which field conflicts to avoid user enumeration (CWE-284)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})

        password_hash = pwd_context.hash(payload.password)

        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, datetime.utcnow().isoformat())
        )
        conn.commit()

        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except (sqlite3.Error, ValidationError):
        # Database error or validation error
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
    finally:
        conn.close()


@app.post("/login")
async def login_user(payload: LoginRequest):
    """
    Authenticate a user with email and password.
    """
    conn = get_db_connection()
    try:
        email = payload.email.strip().lower()
        user = get_user_by_email(conn, email)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

        if not pwd_context.verify(payload.password, user["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

        token = create_access_token(username=user["username"], email=user["email"], user_id=user["id"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    finally:
        conn.close()


@app.post("/set_secret")
async def set_secret(data: SetSecretRequest, token_payload: dict = Depends(get_current_token_payload)):
    """
    Save a secret on the server using the username and the secret text.
    Requires a valid Bearer token where the subject matches the username (CWE-863).
    """
    # Authorization: ensure the token subject matches the requested username
    token_username = token_payload.get("sub")
    if token_username is None or token_username != data.username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        # Ensure user exists
        user = get_user_by_username(conn, data.username)
        if not user:
            # Return 401 for security reasons rather than revealing existence
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

        # Upsert secret securely
        upsert_secret(conn, user_id=user["id"], secret_text=data.secret)
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    finally:
        conn.close()


@app.get("/get_secret")
async def get_secret(username: str, token_payload: dict = Depends(get_current_token_payload)):
    """
    Retrieve a secret based on the provided username.
    Requires a valid Bearer token where the subject matches the username (CWE-863).
    """
    token_username = token_payload.get("sub")
    if token_username is None or token_username != username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        # Ensure user exists
        user = get_user_by_username(conn, username)
        if not user:
            # Hide existence details (CWE-284)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

        secret_value = get_secret_by_user_id(conn, user_id=user["id"])
        return {"secret": secret_value}
    except HTTPException:
        raise
    finally:
        conn.close()


# ---------------------------
# Run the application
# ---------------------------

if __name__ == "__main__":
    # Start ASGI server on specified host and port
    uvicorn.run(app, host="0.0.0.0", port=5000)