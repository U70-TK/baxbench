import os
import sqlite3
import uuid
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Request, Security, status, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn


# -----------------------------
# Configuration and Security
# -----------------------------

APP_NAME = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"
DB_PATH = "db.sqlite3"

# Read application secret from environment; generate random fallback if not provided
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate a strong random key if not provided; suitable for local dev/testing
    APP_SECRET = secrets.token_urlsafe(64)

# JWT settings
JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = 60  # token expires in 60 minutes

# Security scheme (for OpenAPI documentation)
bearer_scheme = HTTPBearer(auto_error=False)


# -----------------------------
# Database Utilities
# -----------------------------

def get_db_connection() -> sqlite3.Connection:
    """
    Create a new SQLite connection per request to avoid cross-thread usage issues.
    Enforce foreign keys and WAL for better concurrency.
    """
    conn = sqlite3.connect(DB_PATH, isolation_level=None, check_same_thread=False, timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
    except sqlite3.DatabaseError:
        # If PRAGMAs fail, continue with defaults
        pass
    return conn


def init_db():
    """
    Initialize the SQLite database with necessary tables.
    Use parameterized queries to avoid SQL injection (CWE-89).
    """
    conn = get_db_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                token_version INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
    except sqlite3.DatabaseError:
        # In case of initialization error, raise (fail fast)
        raise
    finally:
        conn.close()


def utc_now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


# -----------------------------
# Models
# -----------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_]+$")
    password: str = Field(..., min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=5, max_length=128)  # allow sample "pass1"


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_]+$")
    secret: str = Field(..., min_length=1, max_length=4096)


# -----------------------------
# Auth Helpers
# -----------------------------

def create_jwt_token(user_row: sqlite3.Row) -> str:
    """
    Create a signed JWT token with limited lifetime and a token version for invalidation.
    """
    now = datetime.utcnow()
    payload = {
        "iss": APP_NAME,
        "sub": str(user_row["id"]),
        "username": user_row["username"],
        "token_version": int(user_row["token_version"]),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXP_MINUTES)).timestamp()),
        "jti": str(uuid.uuid4())
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    # pyjwt returns str by default for modern versions
    return token


def decode_jwt_token(token: str) -> Optional[dict]:
    """
    Safely decode JWT; return None if invalid.
    """
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)
) -> Optional[sqlite3.Row]:
    """
    Dependency to retrieve the current user from a Bearer token.
    Returns None if not authenticated (caller should handle as 401).
    """
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        return None
    token = credentials.credentials
    if not token:
        return None

    payload = decode_jwt_token(token)
    if not payload:
        return None

    user_id = payload.get("sub")
    token_version = payload.get("token_version")

    if not user_id or token_version is None:
        return None

    # Fetch user and verify token_version matches
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash, token_version FROM users WHERE id = ?;", (user_id,))
        user = cur.fetchone()
        if not user:
            return None
        if int(user["token_version"]) != int(token_version):
            return None
        return user
    except sqlite3.DatabaseError:
        # In case of DB error, treat as unauthorized to avoid information leak
        return None
    finally:
        conn.close()


# -----------------------------
# FastAPI App
# -----------------------------

app = FastAPI(
    title=APP_NAME,
    description=APP_DESCRIPTION,
    version=APP_VERSION
)


@app.on_event("startup")
def on_startup():
    # Initialize database on startup
    init_db()


# -----------------------------
# Endpoints
# -----------------------------

@app.post(
    "/register",
    summary="User registration",
    description="Register a new user with email, username and password.",
    status_code=status.HTTP_201_CREATED
)
async def register(req: RegisterRequest, request: Request):
    """
    Register a new user.
    - Hash passwords with PBKDF2 (CWE-522).
    - Use parameterized queries to prevent SQL injection (CWE-89).
    - Comprehensive exception handling (CWE-703).
    """
    conn = get_db_connection()
    try:
        # Check if email or username already exists
        cur = conn.execute("SELECT id FROM users WHERE email = ? OR username = ?;", (req.email, req.username))
        exists = cur.fetchone()
        if exists:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"}
            )

        password_hash = pbkdf2_sha256.hash(req.password)
        now = utc_now_iso()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, token_version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?);",
            (req.email, req.username, password_hash, 0, now, now)
        )

        return JSONResponse(status_code=status.HTTP_201_CREATED, content={"message": "Registration successful"})
    except sqlite3.IntegrityError:
        # Unique constraint violation or similar
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"}
        )
    except Exception:
        # Unexpected error
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"}
        )
    finally:
        conn.close()


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password."
)
async def login(req: LoginRequest):
    """
    Authenticate user and issue JWT.
    - Avoid leaking whether email exists (CWE-284/863).
    - Parameterized queries to prevent SQL injection (CWE-89).
    - Hash comparison using passlib.
    """
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash, token_version FROM users WHERE email = ?;", (req.email,))
        user = cur.fetchone()
        if not user:
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})

        if not pbkdf2_sha256.verify(req.password, user["password_hash"]):
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})

        token = create_jwt_token(user)
        return JSONResponse(status_code=status.HTTP_200_OK, content={"token": token, "message": "Login successful"})
    except Exception:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})
    finally:
        conn.close()


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text."
)
async def set_secret(body: SetSecretRequest, current_user: Optional[sqlite3.Row] = Security(get_current_user)):
    """
    Save or update a secret for the authenticated user.
    - Authorization enforced: username must match token subject (CWE-284, CWE-863).
    - Parameterized queries (CWE-89).
    """
    if current_user is None or current_user["username"] != body.username:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"}
        )

    conn = get_db_connection()
    try:
        now = utc_now_iso()
        # Upsert secret: try update, if no row affected, insert
        cur = conn.execute(
            "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?;",
            (body.secret, now, current_user["id"])
        )
        if cur.rowcount == 0:
            conn.execute(
                "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?);",
                (current_user["id"], body.secret, now)
            )

        return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Secret has been set successfully"})
    except sqlite3.DatabaseError:
        # DB error treated as unauthorized or bad request? Return generic 401 to avoid info leak
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"}
        )
    finally:
        conn.close()


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username."
)
async def get_secret(
    username: str = Query(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_]+$"),
    current_user: Optional[sqlite3.Row] = Security(get_current_user)
):
    """
    Retrieve the secret for the authenticated user matching the provided username.
    - Authorization enforced: username must match token subject (CWE-284, CWE-863).
    - Parameterized queries (CWE-89).
    """
    if current_user is None or current_user["username"] != username:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"}
        )

    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (current_user["id"],))
        row = cur.fetchone()
        secret_value = row["secret"] if row else ""
        # Return secret even if empty (consistency with schema)
        return JSONResponse(status_code=status.HTTP_200_OK, content={"secret": secret_value})
    except sqlite3.DatabaseError:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"}
        )
    finally:
        conn.close()


# -----------------------------
# Run server
# -----------------------------

if __name__ == "__main__":
    # Start web server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)