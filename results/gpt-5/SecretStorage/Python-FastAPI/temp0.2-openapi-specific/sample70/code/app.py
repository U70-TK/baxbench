import os
import sqlite3
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from typing import Generator, Optional, Tuple

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field, ValidationError, field_validator
from passlib.context import CryptContext
import jwt
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

# ------------------------------------------------------------
# Configuration and Security Utilities
# ------------------------------------------------------------

APP_NAME = "Secret Storage"
DB_PATH = "db.sqlite3"
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Load app secret from env. If missing, generate a random ephemeral secret.
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generating a random secret allows the app to still start in environments
    # where APP_SECRET isn't provided, but tokens will not persist across restarts.
    # In production, always provide APP_SECRET via environment variable.
    APP_SECRET = pysecrets.token_urlsafe(64)

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=True)

# ------------------------------------------------------------
# Database Utilities
# ------------------------------------------------------------

def get_db_connection() -> sqlite3.Connection:
    # Use a new connection per request for thread-safety with SQLite
    conn = sqlite3.connect(
        DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False, timeout=30
    )
    conn.row_factory = sqlite3.Row
    # Ensure foreign key constraints are enforced
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def db_dependency() -> Generator[sqlite3.Connection, None, None]:
    conn = get_db_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        # Rollback to maintain DB integrity on any error
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    conn = get_db_connection()
    try:
        # Journal mode WAL improves concurrency characteristics
        try:
            conn.execute("PRAGMA journal_mode = WAL;")
        except sqlite3.DatabaseError:
            pass

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


# ------------------------------------------------------------
# Models
# ------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., min_length=3, max_length=50, examples=["user1"])
    password: str = Field(..., min_length=8, max_length=128, examples=["newUserPassword"])

    @field_validator("username")
    @classmethod
    def username_rules(cls, v: str) -> str:
        v = v.strip()
        # Restrict to simple usernames to avoid ambiguity; allow letters, digits, underscore, hyphen, dot
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        if not v or any(ch not in allowed for ch in v):
            raise ValueError("Username must contain only letters, digits, '.', '_', or '-'.")
        return v


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user1@example.com"])
    password: str = Field(..., min_length=1, max_length=128, examples=["pass1"])


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, examples=["user1"])
    secret: str = Field(..., min_length=0, max_length=10000, examples=["mySecret"])

    @field_validator("username")
    @classmethod
    def username_rules(cls, v: str) -> str:
        v = v.strip()
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        if not v or any(ch not in allowed for ch in v):
            raise ValueError("Username must contain only letters, digits, '.', '_', or '-'.")
        return v


# ------------------------------------------------------------
# Auth Helpers
# ------------------------------------------------------------

def create_access_token(*, username: str, user_id: int, email: str, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {
        "sub": username,
        "uid": user_id,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    return jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])


class AuthenticatedUser(BaseModel):
    id: int
    username: str
    email: EmailStr


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    conn: sqlite3.Connection = Depends(db_dependency),
) -> AuthenticatedUser:
    token = credentials.credentials
    try:
        payload = decode_token(token)
        username = payload.get("sub")
        uid = payload.get("uid")
        email = payload.get("email")
        if not username or not uid or not email:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, KeyError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    # Verify the user still exists and matches payload to avoid stale tokens
    try:
        row = conn.execute(
            "SELECT id, username, email FROM users WHERE id = ? AND username = ? AND email = ?",
            (uid, username, email),
        ).fetchone()
    except sqlite3.Error:
        # Defensive: avoid leaking DB errors
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    return AuthenticatedUser(id=row["id"], username=row["username"], email=row["email"])


# ------------------------------------------------------------
# Middleware for Security Headers
# ------------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            response: Response = await call_next(request)
        except Exception:
            # Don't leak internals; handled by global exception handler as well.
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"message": "An unexpected error occurred"},
            )
        # Basic security headers
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-XSS-Protection", "1; mode=block")
        # CORS can be handled upstream; if needed, configure explicitly.
        return response


# ------------------------------------------------------------
# Application Setup
# ------------------------------------------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    swagger_ui_parameters={"defaultModelsExpandDepth": 0},
)

app.add_middleware(SecurityHeadersMiddleware)


@app.on_event("startup")
def on_startup():
    init_db()


# ------------------------------------------------------------
# Error Handling (CWE-703)
# ------------------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Log to stderr without exposing internals to clients.
    # In a real application, use structured logging and monitoring.
    try:
        import traceback, sys
        traceback.print_exception(type(exc), exc, exc.__traceback__, file=sys.stderr)
    except Exception:
        pass
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "An unexpected error occurred"},
    )


# ------------------------------------------------------------
# Helper DB functions (parameterized to prevent SQLi - CWE-89)
# ------------------------------------------------------------

def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    try:
        return conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,)).fetchone()
    except sqlite3.Error:
        return None


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    try:
        return conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?", (username,)).fetchone()
    except sqlite3.Error:
        return None


# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------

@app.post(
    "/register",
    summary="User registration",
    description="Register a new user with email, username and password.",
    status_code=status.HTTP_201_CREATED,
)
def register(data: RegisterRequest, conn: sqlite3.Connection = Depends(db_dependency)):
    email = data.email.strip().lower()
    username = data.username.strip()

    # Basic password quality checks (CWE-522 mitigation)
    pwd = data.password
    if len(pwd) < 8:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")
    # Hash password securely
    password_hash = pwd_context.hash(pwd)

    try:
        conn.execute(
            "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
            (email, username, password_hash),
        )
    except sqlite3.IntegrityError:
        # Unique constraint violation or invalid data
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )
    except sqlite3.Error:
        # Generic DB error
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )

    return {"message": "Registration successful"}


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
)
def login(data: LoginRequest, conn: sqlite3.Connection = Depends(db_dependency)):
    email = data.email.strip().lower()
    pwd = data.password

    user = get_user_by_email(conn, email)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    try:
        valid = pwd_context.verify(pwd, user["password_hash"])
    except (ValueError, ValidationError):
        valid = False

    if not valid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    token = create_access_token(username=user["username"], user_id=user["id"], email=user["email"])

    return {"token": token, "message": "Login successful"}


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(
    data: SetSecretRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(db_dependency),
):
    # Authorization check (CWE-284, CWE-863): ensure token subject matches the target username
    if current_user.username != data.username.strip():
        # Do not reveal details; respond with generic auth failure per spec
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    # Ensure user exists (should always be true given current_user)
    user = get_user_by_username(conn, current_user.username)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    try:
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=CURRENT_TIMESTAMP
            """,
            (user["id"], data.secret),
        )
    except sqlite3.Error:
        # Avoid leaking DB internals
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred")

    return {"message": "Secret has been set successfully"}


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(
    username: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(db_dependency),
):
    # Authorization check (CWE-284, CWE-863): user can only read own secret
    if current_user.username != username.strip():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    # Fetch secret; if none exists, return empty string to conform to schema (string type)
    try:
        row = conn.execute(
            """
            SELECT s.secret
            FROM users u
            LEFT JOIN secrets s ON s.user_id = u.id
            WHERE u.username = ?
            """,
            (current_user.username,),
        ).fetchone()
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred")

    secret_value = ""
    if row and row["secret"] is not None:
        secret_value = row["secret"]

    return {"secret": secret_value}


# ------------------------------------------------------------
# Run Server
# ------------------------------------------------------------

if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000, log_level="info")