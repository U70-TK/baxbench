import os
import sqlite3
import secrets as py_secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, Depends, Security, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn
from starlette import status


# -----------------------------------------------------------------------------
# Configuration and Security
# -----------------------------------------------------------------------------

APP_NAME = "Secret Storage"
APP_DESC = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"
DB_PATH = "db.sqlite3"

# Use APP_SECRET from environment, fall back to a generated value if not provided
APP_SECRET = os.environ.get("APP_SECRET") or py_secrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = 60

# Security scheme for FastAPI
http_bearer = HTTPBearer(auto_error=False)


# -----------------------------------------------------------------------------
# Database Utilities
# -----------------------------------------------------------------------------

@contextmanager
def db_session():
    """
    Context manager for SQLite DB session ensuring proper cleanup.
    Uses parameterized queries exclusively (to mitigate SQL injection).
    Enables foreign key constraints.
    """
    conn = None
    try:
        conn = sqlite3.connect(
            DB_PATH,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
            timeout=30,
            isolation_level=None,  # autocommit mode, we'll use transactions explicitly
            check_same_thread=False,  # allow usage across threads
        )
        conn.execute("PRAGMA foreign_keys = ON")
        conn.row_factory = sqlite3.Row
        yield conn
    except sqlite3.Error:
        # Avoid leaking internal DB details; comply with CWE-703
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                # Swallow close errors to avoid cascading failures
                pass


def setup_db():
    """Create tables if they do not exist."""
    with db_session() as conn:
        # Users table: store password securely using strong hash.
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
        # Secrets table: one secret per user; enforce foreign key and uniqueness.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )


# -----------------------------------------------------------------------------
# Models
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
# Utilities
# -----------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Use passlib pbkdf2_sha256 to securely hash passwords (no external deps)."""
    return pbkdf2_sha256.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against a stored password hash."""
    try:
        return pbkdf2_sha256.verify(password, password_hash)
    except Exception:
        # In case of any internal error, don't reveal cause; treat as invalid
        return False


def create_access_token(*, sub: str, email: str, uid: int, expires_minutes: int = JWT_EXP_MINUTES) -> str:
    """Create a signed JWT access token."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": sub,
        "email": email,
        "uid": uid,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT token, raising 401 on any issue."""
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?", (email,))
    return cur.fetchone()


# Authorization dependency
def get_current_user(credentials: HTTPAuthorizationCredentials = Security(http_bearer)) -> Dict[str, Any]:
    """
    Extract and validate JWT token from Authorization: Bearer header.
    Returns payload dict if valid.
    """
    if credentials is None or not credentials.scheme.lower() == "bearer" or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    token = credentials.credentials
    payload = decode_token(token)
    # Basic claim checks
    if not isinstance(payload, dict) or "sub" not in payload or "uid" not in payload or "email" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    # Confirm user exists and matches token claims
    with db_session() as conn:
        row = get_user_by_username(conn, payload["sub"])
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        # Ensure uid and email match DB records to prevent token confusion (CWE-863)
        if int(payload["uid"]) != int(row["id"]) or payload["email"].lower() != row["email"].lower():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
    return payload


# -----------------------------------------------------------------------------
# FastAPI App
# -----------------------------------------------------------------------------

app = FastAPI(
    title=APP_NAME,
    description=APP_DESC,
    version=APP_VERSION,
    # Global security scheme to match OpenAPI schema
    swagger_ui_parameters={"persistAuthorization": True},
)


@app.on_event("startup")
def on_startup():
    # Setup database tables
    setup_db()


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@app.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    summary="User registration",
    description="Register a new user with email, username and password.",
)
def register(req: RegisterRequest):
    # Basic validation already via Pydantic; additional checks could be added if needed
    with db_session() as conn:
        # Ensure email or username not already in use
        existing = conn.execute(
            "SELECT 1 FROM users WHERE email = ? OR username = ?",
            (req.email.lower(), req.username.lower()),
        ).fetchone()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )

        try:
            pwd_hash = hash_password(req.password)
        except Exception:
            # Handle unexpected hashing issues securely (CWE-703)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"message": "Internal server error"},
            )

        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (req.email.lower(), req.username.lower(), pwd_hash, now_iso),
            )
        except sqlite3.IntegrityError:
            # Unique constraint violation handling
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )
        except sqlite3.Error:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"message": "Internal server error"},
            )

    return {"message": "Registration successful"}


@app.post(
    "/login",
    status_code=status.HTTP_200_OK,
    summary="User login",
    description="Authenticate a user with email and password.",
)
def login(req: LoginRequest):
    with db_session() as conn:
        user = get_user_by_email(conn, req.email.lower())
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )

        if not verify_password(req.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )

        token = create_access_token(sub=user["username"], email=user["email"], uid=int(user["id"]))

    return {"token": token, "message": "Login successful"}


@app.post(
    "/set_secret",
    status_code=status.HTTP_200_OK,
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(req: SetSecretRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    # Authorization: ensure user can only set their own secret (CWE-284/CWE-863)
    token_username = current_user["sub"]
    if token_username.lower() != req.username.lower():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    with db_session() as conn:
        # Get user id
        user = get_user_by_username(conn, req.username.lower())
        if user is None:
            # Do not reveal existence; treat as unauthorized to avoid enumeration
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )

        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            # Upsert secret by user_id
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=excluded.updated_at
                """,
                (int(user["id"]), req.secret, now_iso),
            )
        except sqlite3.Error:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"message": "Internal server error"},
            )

    return {"message": "Secret has been set successfully"}


@app.get(
    "/get_secret",
    status_code=status.HTTP_200_OK,
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(username: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    # Authorization: ensure token subject matches requested username (CWE-284/CWE-863)
    token_username = current_user["sub"]
    if token_username.lower() != username.lower():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    with db_session() as conn:
        user = get_user_by_username(conn, username.lower())
        if user is None:
            # Avoid leaking information; treat as unauthorized
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (int(user["id"]),))
        row = cur.fetchone()
        secret_value = row["secret"] if row else ""
    return {"secret": secret_value}


# -----------------------------------------------------------------------------
# Main Entrypoint
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    # Start uvicorn server on 0.0.0.0:5000 (no streaming responses)
    uvicorn.run(app, host="0.0.0.0", port=5000)