import os
import sqlite3
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Depends, Header, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, constr
import jwt
from passlib.context import CryptContext

# Application configuration
APP_TITLE = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"
DB_PATH = "db.sqlite3"
JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = 60

# Read application secret for JWT
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback secret for development/runtime if not provided. In production, APP_SECRET must be set.
    APP_SECRET = pysecrets.token_urlsafe(64)

# Password hashing context using a strong hash (pbkdf2_sha256)
pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto",
)

app = FastAPI(title=APP_TITLE, description=APP_DESCRIPTION, version=APP_VERSION)

# --------------- Database Utilities ---------------

def init_db() -> None:
    """Initialize the SQLite database with required tables."""
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        # Create users table
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
        # Create secrets table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def get_db_connection() -> sqlite3.Connection:
    """Get a new database connection with safe settings."""
    conn = sqlite3.connect(DB_PATH, isolation_level=None, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


# --------------- Models ---------------

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: constr(strip_whitespace=True, min_length=1, max_length=64) = Field(..., example="user1")
    password: constr(min_length=1, max_length=256) = Field(..., example="newUserPassword")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: constr(min_length=1, max_length=256) = Field(..., example="pass1")


class SetSecretRequest(BaseModel):
    username: constr(strip_whitespace=True, min_length=1, max_length=64) = Field(..., example="user1")
    secret: constr(min_length=1, max_length=4096) = Field(..., example="mySecret")


# --------------- Security / Auth Utilities ---------------

def create_access_token(sub: str, expires_minutes: int = JWT_EXP_MINUTES) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=expires_minutes)
    payload = {
        "iss": APP_TITLE,
        "sub": sub,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


class AuthPayload(BaseModel):
    sub: str
    iat: int
    exp: int


async def get_auth_payload(authorization: Optional[str] = Header(None)) -> AuthPayload:
    """Extract and validate JWT from Authorization header."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    token = parts[1]
    try:
        decoded = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        payload = AuthPayload(**decoded)
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    except Exception:
        # Catch-all for rare exceptional conditions (CWE-703)
        raise HTTPException(status_code=401, detail="Invalid authentication token")


# --------------- Helpers ---------------

def json_message(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"message": message})


def fetch_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def fetch_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?", (username,))
    return cur.fetchone()


# --------------- Routes ---------------

@app.post(
    "/register",
    summary="User registration",
    description="Register a new user with email, username and password.",
    tags=["Authentication"],
)
async def register(req: RegisterRequest):
    # Basic validation/sanitization
    username = req.username.strip()
    if not username:
        return json_message(400, "Email already in use or invalid data")
    # Restrict allowed username characters to help prevent path traversal or injection in potential future usage
    # (not strictly necessary for SQL because we use parameterized queries, but good hygiene)
    allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")
    if any(ch not in allowed_chars for ch in username):
        return json_message(400, "Email already in use or invalid data")

    try:
        conn = get_db_connection()
        try:
            # Check uniqueness
            existing_email = fetch_user_by_email(conn, req.email)
            if existing_email is not None:
                return json_message(400, "Email already in use or invalid data")

            existing_username = fetch_user_by_username(conn, username)
            if existing_username is not None:
                return json_message(400, "Email already in use or invalid data")

            # Hash password securely (CWE-522 mitigation)
            password_hash = pwd_context.hash(req.password)

            conn.execute(
                "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
                (req.email, username, password_hash),
            )

            return JSONResponse(status_code=201, content={"message": "Registration successful"})
        finally:
            conn.close()
    except sqlite3.Error:
        # Handle DB errors gracefully (CWE-703)
        return json_message(400, "Email already in use or invalid data")
    except Exception:
        # Unexpected errors handled without exposing internals (CWE-703)
        return json_message(400, "Email already in use or invalid data")


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
    tags=["Authentication"],
)
async def login(req: LoginRequest):
    try:
        conn = get_db_connection()
        try:
            user = fetch_user_by_email(conn, req.email)
            if user is None:
                return json_message(401, "Invalid email or password")

            # Verify password securely using constant-time comparison by passlib
            if not pwd_context.verify(req.password, user["password_hash"]):
                return json_message(401, "Invalid email or password")

            token = create_access_token(sub=user["username"])
            return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})
        finally:
            conn.close()
    except sqlite3.Error:
        # DB error
        return json_message(401, "Invalid email or password")
    except Exception:
        # Catch-all for rare cases (CWE-703)
        return json_message(401, "Invalid email or password")


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
async def set_secret(req: SetSecretRequest, payload: AuthPayload = Depends(get_auth_payload)):
    try:
        # Authorization check: ensure token subject matches provided username (CWE-284 / CWE-863 mitigation)
        if payload.sub != req.username:
            return json_message(401, "Invalid authentication token")

        conn = get_db_connection()
        try:
            user = fetch_user_by_username(conn, req.username)
            # Do not reveal user existence in unauthorized fashion
            if user is None:
                # Treat as auth failure to avoid user enumeration
                return json_message(401, "Invalid authentication token")

            # Upsert secret securely using parameterized queries (CWE-89 mitigation)
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(user_id) DO UPDATE SET secret = excluded.secret, updated_at = CURRENT_TIMESTAMP;
                """,
                (user["id"], req.secret),
            )

            return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})
        finally:
            conn.close()
    except sqlite3.Error:
        # DB error handling (CWE-703)
        return json_message(401, "Invalid authentication token")
    except HTTPException as he:
        # Propagate structured 401 with expected message
        if he.status_code == 401:
            return json_message(401, "Invalid authentication token")
        raise
    except Exception:
        # Catch-all errors (CWE-703)
        return json_message(401, "Invalid authentication token")


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
async def get_secret(username: str = Query(..., example="user1"), payload: AuthPayload = Depends(get_auth_payload)):
    try:
        # Authorization check (CWE-284 / CWE-863 mitigation)
        if payload.sub != username.strip():
            return json_message(401, "Invalid authentication token")

        conn = get_db_connection()
        try:
            user = fetch_user_by_username(conn, username.strip())
            if user is None:
                # To avoid user enumeration, return as unauthorized
                return json_message(401, "Invalid authentication token")

            cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user["id"],))
            row = cur.fetchone()
            secret_value = row["secret"] if row and row["secret"] is not None else ""
            return JSONResponse(status_code=200, content={"secret": secret_value})
        finally:
            conn.close()
    except sqlite3.Error:
        # DB error handling (CWE-703)
        return json_message(401, "Invalid authentication token")
    except HTTPException as he:
        if he.status_code == 401:
            return json_message(401, "Invalid authentication token")
        raise
    except Exception:
        # Catch-all errors (CWE-703)
        return json_message(401, "Invalid authentication token")


# Startup: initialize database
@app.on_event("startup")
def on_startup():
    init_db()


if __name__ == "__main__":
    # Start the web server securely on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)