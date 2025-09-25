import os
import sqlite3
import logging
import secrets as std_secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from fastapi import FastAPI, Depends, HTTPException, status, Request, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn

# ----------------------------
# Configuration and Security
# ----------------------------
APP_NAME = "Secret Storage"
APP_VERSION = "1.0.0"
DB_PATH = "db.sqlite3"

logger = logging.getLogger(APP_NAME)
logging.basicConfig(level=logging.INFO)

APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Generate a strong ephemeral secret if none provided.
    # Note: For production, always set APP_SECRET via environment.
    APP_SECRET = std_secrets.token_urlsafe(64)
    logger.warning("APP_SECRET not set. Using ephemeral secret; tokens will be invalid after restart.")

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# ----------------------------
# FastAPI initialization
# ----------------------------
app = FastAPI(
    title=APP_NAME,
    description="A secure cloud storage app for string secrets.",
    version=APP_VERSION,
    openapi_tags=[{"name": "Authentication", "description": "Operations related to user authentication"}],
)

bearer_scheme = HTTPBearer(auto_error=True)

# ----------------------------
# Database utilities
# ----------------------------

def get_db_connection() -> sqlite3.Connection:
    """
    Create a new SQLite connection for each request to avoid shared-state issues.
    Use row_factory for dict-like access and ensure foreign keys are enforced.
    """
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.Error as e:
        logger.error(f"SQLite PRAGMA setup error: {e}")
    return conn


def init_db() -> None:
    """
    Initialize tables if they do not exist.
    Users: email(unique), username(unique), password_hash
    Secrets: one per user (user_id unique), secret text
    """
    conn = get_db_connection()
    try:
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
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}")
        raise
    finally:
        conn.close()


@app.on_event("startup")
def on_startup() -> None:
    try:
        init_db()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.critical(f"Failed to initialize database on startup: {e}")
        # Let the exception bubble up. It will fail fast instead of running with bad state.


# ----------------------------
# Models
# ----------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_\.]+$")
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_\.]+$")
    secret: str = Field(min_length=1, max_length=4096)


# ----------------------------
# Auth helpers
# ----------------------------

def create_access_token(subject: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token with HS256 algorithm.
    Payload includes 'sub' (user claims) and 'exp' expiry.
    """
    now = datetime.now(timezone.utc)
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = now + expires_delta
    payload = {
        "sub": subject,  # subject can include user_id, username, email
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "nbf": int(now.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    """
    Decode a JWT token safely and return payload.
    Raises HTTPException(401) for invalid tokens.
    """
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        if "sub" not in payload or not isinstance(payload["sub"], dict):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
            )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> sqlite3.Row:
    """
    Extract and validate the JWT token from Authorization header.
    Return the current user row from the database.
    """
    token = credentials.credentials
    payload = decode_token(token)
    sub = payload.get("sub", {})
    user_id = sub.get("user_id")
    username = sub.get("username")
    email = sub.get("email")
    if user_id is None or username is None or email is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    conn = get_db_connection()
    try:
        row = conn.execute("SELECT id, email, username FROM users WHERE id = ?;", (user_id,)).fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
            )
        # Cross-check to prevent token substitution attacks
        if row["username"] != username or row["email"] != email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
            )
        return row
    except sqlite3.Error:
        # On DB error, deny access to avoid leaking state
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    finally:
        conn.close()


# ----------------------------
# Helper functions
# ----------------------------

def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    try:
        return conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?;",
            (email,),
        ).fetchone()
    except sqlite3.Error as e:
        logger.error(f"DB error get_user_by_email: {e}")
        return None


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    try:
        return conn.execute(
            "SELECT id, email, username FROM users WHERE username = ?;",
            (username,),
        ).fetchone()
    except sqlite3.Error as e:
        logger.error(f"DB error get_user_by_username: {e}")
        return None


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret_text: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    try:
        # Use SQLite UPSERT to avoid race conditions.
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret = excluded.secret,
                updated_at = excluded.updated_at;
            """,
            (user_id, secret_text, now),
        )
    except sqlite3.Error as e:
        logger.error(f"DB error upsert_secret: {e}")
        raise


def get_secret_by_user_id(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    try:
        row = conn.execute(
            "SELECT secret FROM secrets WHERE user_id = ?;",
            (user_id,),
        ).fetchone()
        if row:
            return row["secret"]
        return None
    except sqlite3.Error as e:
        logger.error(f"DB error get_secret_by_user_id: {e}")
        return None


# ----------------------------
# Exception handlers
# ----------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}")
    # Avoid leaking internal errors; return a generic 500.
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "An unexpected error occurred"},
    )


# ----------------------------
# Routes
# ----------------------------

@app.post(
    "/register",
    summary="User registration",
    tags=["Authentication"],
    status_code=status.HTTP_201_CREATED,
)
def register(payload: RegisterRequest):
    """
    Register a new user with email, username and password.
    - Validates email format.
    - Hashes password using PBKDF2-SHA256.
    - Ensures unique email and username.
    """
    conn = get_db_connection()
    try:
        # Check if email or username already exists
        existing_email = conn.execute("SELECT 1 FROM users WHERE email = ?;", (payload.email,)).fetchone()
        existing_username = conn.execute("SELECT 1 FROM users WHERE username = ?;", (payload.username,)).fetchone()
        if existing_email or existing_username:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use or invalid data",
            )

        password_hash = pbkdf2_sha256.hash(payload.password)
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (payload.email, payload.username, password_hash, now),
        )
        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except sqlite3.Error as e:
        logger.error(f"DB error register: {e}")
        # Treat DB constraint errors as invalid data to avoid exposing internals
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )
    finally:
        conn.close()


@app.post(
    "/login",
    summary="User login",
    tags=["Authentication"],
)
def login(payload: LoginRequest):
    """
    Authenticate a user with email and password.
    Returns a JWT token on success.
    """
    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, payload.email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )

        stored_hash = user["password_hash"]
        # Verify password in constant time via passlib
        if not pbkdf2_sha256.verify(payload.password, stored_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )

        subject = {
            "user_id": user["id"],
            "username": user["username"],
            "email": user["email"],
        }
        token = create_access_token(subject=subject)
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except sqlite3.Error as e:
        logger.error(f"DB error login: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    finally:
        conn.close()


@app.post(
    "/set_secret",
    summary="Set secret",
)
def set_secret(payload: SetSecretRequest, current_user: sqlite3.Row = Depends(get_current_user)):
    """
    Save a secret on the server using the username in the payload and the bearer token.
    Ensures that the token corresponds to the provided username to prevent IDOR.
    """
    # Authorization check: ensure the requester is the owner of the username
    if current_user["username"] != payload.username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    conn = get_db_connection()
    try:
        upsert_secret(conn, current_user["id"], payload.secret)
        return {"message": "Secret has been set successfully"}
    except sqlite3.Error:
        # Handle exceptional conditions securely
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred",
        )
    finally:
        conn.close()


@app.get(
    "/get_secret",
    summary="Get secret",
)
def get_secret(username: str = Query(...), current_user: sqlite3.Row = Depends(get_current_user)):
    """
    Retrieve a secret based on the provided username.
    Ensures that the requester can only retrieve their own secret.
    """
    if not isinstance(username, str) or not (3 <= len(username) <= 32):
        # Minimal validation aligned with model constraints
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    # Authorization check: ensure requester is owner
    if current_user["username"] != username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    conn = get_db_connection()
    try:
        secret = get_secret_by_user_id(conn, current_user["id"])
        # If no secret set, return empty string as a safe default
        return {"secret": secret if secret is not None else ""}
    except sqlite3.Error:
        # Avoid leaking information on DB errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred",
        )
    finally:
        conn.close()


# ----------------------------
# Run server
# ----------------------------

if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)