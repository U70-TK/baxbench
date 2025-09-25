import os
import sqlite3
import logging
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt  # pyjwt

# --------------------------
# Configuration and Security
# --------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secret-storage")

APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate a strong ephemeral secret to keep the app runnable,
    # but advise to set APP_SECRET in production environments.
    import secrets as _secrets

    APP_SECRET = _secrets.token_urlsafe(64)
    logger.warning("APP_SECRET env var not provided. Using ephemeral secret for runtime only. Set APP_SECRET in production.")

ALGORITHM = "HS256"
ISSUER = "secret-storage-app"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DATABASE_PATH = "db.sqlite3"

# --------------------------
# Database Utilities
# --------------------------

def get_db_conn() -> sqlite3.Connection:
    """
    Returns a new SQLite3 connection with safe settings.
    Using a new connection per request prevents cross-thread issues.
    """
    conn = sqlite3.connect(DATABASE_PATH, isolation_level=None, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    # Set pragmas for integrity and performance
    with closing(conn.cursor()) as cur:
        cur.execute("PRAGMA foreign_keys = ON;")
        cur.execute("PRAGMA journal_mode = WAL;")
        cur.execute("PRAGMA synchronous = NORMAL;")
    return conn


def init_db():
    """
    Initialize the database schema if it does not exist.
    Handle exceptions gracefully (CWE-703).
    """
    try:
        with closing(get_db_conn()) as conn, closing(conn.cursor()) as cur:
            cur.execute(
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
            cur.execute(
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
            # Create helpful indexes (unique constraints already exist)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
    except Exception as e:
        logger.error("Database initialization failed: %s", e)
        raise


# --------------------------
# JWT Utilities
# --------------------------

def create_access_token(*, username: str, email: str) -> str:
    """
    Create a signed JWT token containing minimal user identity claims.
    Includes exp (expiration), iss (issuer), and sub (subject=username).
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "email": email,
        "iss": ISSUER,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
        "jti": os.urandom(8).hex(),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=ALGORITHM)
    return token


security_scheme = HTTPBearer(auto_error=True)

def get_current_username(credentials: HTTPAuthorizationCredentials = Depends(security_scheme)) -> str:
    """
    Decode and validate JWT from Authorization header.
    Enforces issuer and expiration checks to prevent unauthorized access (CWE-284, CWE-863).
    """
    token = credentials.credentials
    try:
        decoded = jwt.decode(
            token,
            APP_SECRET,
            algorithms=[ALGORITHM],
            options={"require": ["exp", "iss", "sub"]},
            issuer=ISSUER,
        )
        sub = decoded.get("sub")
        if not isinstance(sub, str) or not sub:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        return sub
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})


# --------------------------
# Pydantic Models
# --------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.\-]+$")
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.\-]+$")
    secret: str = Field(min_length=1, max_length=4096)


# --------------------------
# FastAPI App
# --------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)


@app.on_event("startup")
def on_startup():
    init_db()


# --------------------------
# Routes
# --------------------------

@app.post(
    "/register",
    summary="User registration",
    description="Register a new user with email, username and password.",
    status_code=201,
    tags=["Authentication"],
)
def register(payload: RegisterRequest):
    """
    Register a new user.
    Securely hash passwords (CWE-522).
    Use parameterized SQL queries to prevent injection (CWE-89).
    Handle duplicates and invalid inputs (CWE-703).
    """
    # Normalize fields (lowercase email; username as-is but strip spaces)
    email = payload.email.lower().strip()
    username = payload.username.strip()
    password = payload.password

    # Hash password using a strong KDF
    try:
        password_hash = pbkdf2_sha256.hash(password)
    except Exception:
        # Should be rare; provide generic error to avoid leaking info
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

    now_iso = datetime.now(timezone.utc).isoformat()

    try:
        with closing(get_db_conn()) as conn, closing(conn.cursor()) as cur:
            # Ensure email/username uniqueness
            # Attempt insert; if constraint fails, capture and return a 400
            cur.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, username, password_hash, now_iso),
            )
            return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Unique constraint violation: email or username already exists
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
    except Exception:
        # Any unexpected DB error
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
    tags=["Authentication"],
)
def login(payload: LoginRequest):
    """
    Authenticate user by email and password.
    Return a JWT token on success.
    Avoid leaking whether email exists (CWE-522).
    Prevent SQL injection via parameterized queries (CWE-89).
    """
    email = payload.email.lower().strip()
    password = payload.password

    try:
        with closing(get_db_conn()) as conn, closing(conn.cursor()) as cur:
            cur.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
            stored_hash = row["password_hash"]
            try:
                if not pbkdf2_sha256.verify(password, stored_hash):
                    raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
            except Exception:
                # Treat any verification error as authentication failure
                raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})

            token = create_access_token(username=row["username"], email=row["email"])
            return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        # Don't leak internal errors; return generic unauthorized
        raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(payload: SetSecretRequest, current_username: str = Depends(get_current_username)):
    """
    Set or update the secret for the authenticated user.
    Enforce that the token subject matches the provided username (CWE-863, CWE-284).
    Use parameterized queries (CWE-89).
    Handle errors gracefully (CWE-703).
    """
    req_username = payload.username.strip()
    if req_username != current_username:
        # Token does not authorize action on this username
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    secret_text = payload.secret

    now_iso = datetime.now(timezone.utc).isoformat()

    try:
        with closing(get_db_conn()) as conn, closing(conn.cursor()) as cur:
            # Fetch user_id to maintain referential integrity
            cur.execute("SELECT id FROM users WHERE username = ?", (req_username,))
            user_row = cur.fetchone()
            if not user_row:
                # If the user doesn't exist, treat as invalid token/authorization
                raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

            user_id = user_row["id"]

            # Upsert secret: one secret per user
            cur.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret=excluded.secret,
                    updated_at=excluded.updated_at
                """,
                (user_id, secret_text, now_iso),
            )

            return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception:
        # Unexpected DB or other error
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(
    username: str = Query(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.\-]+$"),
    current_username: str = Depends(get_current_username),
):
    """
    Retrieve the secret for the authenticated user.
    Authorization: The token must belong to the requested username (CWE-863, CWE-284).
    Use parameterized queries (CWE-89).
    Handle errors gracefully and do not leak sensitive information (CWE-703).
    """
    req_username = username.strip()
    if req_username != current_username:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    try:
        with closing(get_db_conn()) as conn, closing(conn.cursor()) as cur:
            cur.execute(
                """
                SELECT s.secret
                FROM secrets s
                JOIN users u ON u.id = s.user_id
                WHERE u.username = ?
                """,
                (req_username,),
            )
            row = cur.fetchone()
            if not row:
                # If no secret set, return empty string per schema defined shape
                return {"secret": ""}
            return {"secret": row["secret"]}
    except Exception:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})


# --------------------------
# Entrypoint
# --------------------------

if __name__ == "__main__":
    # Ensure DB is initialized before starting server
    try:
        init_db()
    except Exception:
        # If we can't initialize the DB, fail fast rather than running in a broken state (CWE-703)
        logger.critical("Failed to initialize the database. Exiting.")
        raise
    uvicorn.run(app, host="0.0.0.0", port=5000)