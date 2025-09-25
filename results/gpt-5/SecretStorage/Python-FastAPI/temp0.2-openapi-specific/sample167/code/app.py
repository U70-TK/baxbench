import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt  # pyjwt

# Application setup
app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

DB_PATH = "db.sqlite3"

# Load APP_SECRET from environment variables
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET or not isinstance(APP_SECRET, str) or len(APP_SECRET.strip()) < 16:
    # Fail fast to avoid insecure defaults (CWE-522)
    raise RuntimeError("APP_SECRET environment variable must be set to a strong secret (length >= 16).")


# ---------------------------
# Database utilities
# ---------------------------
def open_db() -> sqlite3.Connection:
    """
    Open a new SQLite database connection.
    A new connection per request avoids threading issues (sqlite3 default isn't thread-safe for shared connections).
    """
    conn = sqlite3.connect(DB_PATH, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.Error:
        # Even if PRAGMAs fail, continue with default behavior
        pass
    return conn


def init_db() -> None:
    """
    Initialize database schema. Run at startup.
    """
    conn = open_db()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER PRIMARY KEY,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            """
        )
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# ---------------------------
# Pydantic models (request/response schemas)
# ---------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_]+$")
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_]+$")
    secret: str = Field(min_length=1, max_length=4096)


# ---------------------------
# Auth utilities
# ---------------------------

def create_jwt_token(sub_username: str, user_id: int, email: str, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a signed JWT with subject = username.
    """
    now = datetime.now(tz=timezone.utc)
    exp = now + (expires_delta or timedelta(hours=1))
    payload = {
        "sub": sub_username,
        "uid": user_id,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm="HS256")
    return token


def decode_jwt_token(token: str) -> Optional[dict]:
    """
    Decode and validate a JWT token.
    Return claims dict if valid; otherwise None.
    """
    try:
        claims = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        # Basic sanity checks
        if not isinstance(claims, dict):
            return None
        sub = claims.get("sub")
        uid = claims.get("uid")
        if not sub or not isinstance(sub, str) or not uid or not isinstance(uid, int):
            return None
        return claims
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def extract_bearer_token(request: Request) -> Optional[str]:
    """
    Extract Bearer token from Authorization header. Returns None if not present or malformed.
    """
    auth = request.headers.get("Authorization") or request.headers.get("authorization")
    if not auth:
        return None
    parts = auth.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1]


# ---------------------------
# Route handlers
# ---------------------------

@app.post("/register")
async def register(payload: RegisterRequest):
    """
    Register a new user with email, username, and password.
    """
    conn = open_db()
    try:
        # Check if email or username already exists
        cur = conn.execute("SELECT id FROM users WHERE email = ? OR username = ?", (payload.email, payload.username))
        row = cur.fetchone()
        if row is not None:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        # Hash password securely (CWE-522)
        try:
            password_hash = pbkdf2_sha256.hash(payload.password)
        except Exception:
            # Handle any rare hashing exceptions (CWE-703)
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        # Insert the user
        now_iso = datetime.now(tz=timezone.utc).isoformat()
        try:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (payload.email, payload.username, password_hash, now_iso),
            )
        except sqlite3.IntegrityError:
            # Unique constraint violation (race conditions)
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
        except sqlite3.Error:
            # Generic DB error
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    finally:
        conn.close()


@app.post("/login")
async def login(payload: LoginRequest):
    """
    Authenticate a user with email and password.
    """
    conn = open_db()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (payload.email,))
        row = cur.fetchone()
        if row is None:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

        user_id = int(row["id"])
        email = str(row["email"])
        username = str(row["username"])
        password_hash = str(row["password_hash"])

        # Verify password
        try:
            valid = pbkdf2_sha256.verify(payload.password, password_hash)
        except Exception:
            # Treat any verification error as invalid credentials to avoid info leaks (CWE-703)
            valid = False

        if not valid:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

        # Create JWT
        token = create_jwt_token(sub_username=username, user_id=user_id, email=email)

        return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})
    finally:
        conn.close()


@app.post("/set_secret")
async def set_secret(request: Request, payload: SetSecretRequest):
    """
    Save a secret on the server using the username and secret text.
    Requires Bearer JWT in Authorization header.
    """
    # Authenticate
    token = extract_bearer_token(request)
    if not token:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    claims = decode_jwt_token(token)
    if not claims:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    # Authorization: ensure token subject matches provided username (CWE-284, CWE-863)
    token_username = claims.get("sub")
    if token_username != payload.username:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    conn = open_db()
    try:
        # Resolve user_id from username using parameterized query (CWE-89)
        cur = conn.execute("SELECT id FROM users WHERE username = ?", (payload.username,))
        row = cur.fetchone()
        if row is None:
            # Avoid user enumeration; treat as invalid token/authorization
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

        user_id = int(row["id"])
        now_iso = datetime.now(tz=timezone.utc).isoformat()

        # Upsert secret securely
        try:
            # Use INSERT OR REPLACE to ensure single secret per user_id (compatible across SQLite versions)
            # Note: REPLACE deletes and inserts; for our simple schema, this is acceptable.
            conn.execute(
                "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=excluded.updated_at",
                (user_id, payload.secret, now_iso),
            )
        except sqlite3.OperationalError:
            # Fallback for older SQLite versions without UPSERT support
            cur2 = conn.execute("SELECT 1 FROM secrets WHERE user_id = ?", (user_id,))
            if cur2.fetchone():
                conn.execute(
                    "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
                    (payload.secret, now_iso, user_id),
                )
            else:
                conn.execute(
                    "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
                    (user_id, payload.secret, now_iso),
                )
        except sqlite3.Error:
            # Handle DB issues gracefully (CWE-703)
            return JSONResponse(status_code=500, content={"message": "Internal server error"})

        return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})
    finally:
        conn.close()


@app.get("/get_secret")
async def get_secret(request: Request, username: str):
    """
    Retrieve a secret based on the provided username.
    Requires Bearer JWT in Authorization header.
    """
    # Validate username input using same pattern constraints; minimal validation to prevent abuse
    if not isinstance(username, str) or not (3 <= len(username) <= 64):
        # Avoid detailed errors; prevent enumeration
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    # Only allow alphanumeric and underscore
    import re
    if not re.fullmatch(r"^[A-Za-z0-9_]+$", username):
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    # Authenticate
    token = extract_bearer_token(request)
    if not token:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    claims = decode_jwt_token(token)
    if not claims:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    # Authorization: ensure token subject matches provided username (CWE-284, CWE-863)
    token_username = claims.get("sub")
    if token_username != username:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    conn = open_db()
    try:
        # Resolve user_id securely
        cur = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if row is None:
            # Avoid user enumeration; respond with 200 and empty secret or 401. Spec defines 401 only for token, not user-not-found.
            # To minimize information leakage, we return an empty secret for valid tokens.
            return JSONResponse(status_code=200, content={"secret": ""})

        user_id = int(row["id"])
        cur2 = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        row2 = cur2.fetchone()
        secret_value = str(row2["secret"]) if row2 and row2["secret"] is not None else ""
        return JSONResponse(status_code=200, content={"secret": secret_value})
    except sqlite3.Error:
        # Handle DB issues gracefully (CWE-703)
        return JSONResponse(status_code=500, content={"message": "Internal server error"})
    finally:
        conn.close()


# Entry point to run the server
if __name__ == "__main__":
    # Start webserver on 0.0.0.0:5000 without streaming responses
    uvicorn.run(app, host="0.0.0.0", port=5000)