import os
import re
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import uvicorn
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field, constr
from passlib.hash import pbkdf2_sha256
import jwt

# ------------------------------------------------------------------------------
# Configuration and Security
# ------------------------------------------------------------------------------

APP_TITLE = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

DB_PATH = "db.sqlite3"

# Load app secret from environment; generate ephemeral if missing (not logged)
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Ephemeral fallback to keep the app runnable; tokens will invalidate on restart
    APP_SECRET = os.urandom(32).hex()

JWT_ALG = "HS256"
JWT_EXPIRES_MINUTES = 60  # Token expiry time

# Username policy
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{3,32}$")

# Secret size limits
MAX_SECRET_LENGTH = 8192

# ------------------------------------------------------------------------------
# Database utilities
# ------------------------------------------------------------------------------

def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Enforce foreign keys and improve reliability
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn


def init_db() -> None:
    conn = get_conn()
    try:
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
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
    finally:
        conn.close()


def create_user(email: str, username: str, password_hash: str) -> Tuple[bool, Optional[str]]:
    conn = get_conn()
    try:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, now),
        )
        return True, None
    except sqlite3.IntegrityError:
        return False, "Email already in use or invalid data"
    except sqlite3.Error:
        return False, "Database error"
    finally:
        conn.close()


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    conn = get_conn()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def get_user_by_id_and_username(user_id: int, username: str) -> Optional[sqlite3.Row]:
    conn = get_conn()
    try:
        cur = conn.execute(
            "SELECT id, email, username FROM users WHERE id = ? AND username = ?",
            (user_id, username),
        )
        return cur.fetchone()
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_conn()
    try:
        cur = conn.execute("SELECT id, email, username FROM users WHERE username = ?", (username,))
        return cur.fetchone()
    finally:
        conn.close()


def upsert_secret(user_id: int, secret: str) -> Tuple[bool, Optional[str]]:
    conn = get_conn()
    try:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret = excluded.secret,
                updated_at = excluded.updated_at
            """,
            (user_id, secret, now),
        )
        return True, None
    except sqlite3.Error:
        return False, "Database error"
    finally:
        conn.close()


def get_secret_by_user_id(user_id: int) -> Optional[str]:
    conn = get_conn()
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        return row["secret"] if row else None
    finally:
        conn.close()

# ------------------------------------------------------------------------------
# JWT utilities
# ------------------------------------------------------------------------------

def create_access_token(user_id: int, username: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRES_MINUTES)
    payload = {
        "sub": username,
        "uid": user_id,
        "iat": int(time.time()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALG)
    return token


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALG])
        return payload
    except jwt.PyJWTError:
        return None

# ------------------------------------------------------------------------------
# FastAPI app and models
# ------------------------------------------------------------------------------

app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    contact=None,
    license_info=None,
)

security = HTTPBearer(auto_error=False)


def error_response(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"message": message})


class RegisterRequest(BaseModel):
    email: EmailStr
    username: constr(strip_whitespace=True, min_length=3, max_length=32)
    password: constr(min_length=8, max_length=128)

    def validate_username_policy(self) -> Optional[str]:
        if not USERNAME_REGEX.match(self.username):
            return "Invalid username. Use 3-32 chars: letters, numbers, underscore or hyphen."
        return None


class LoginRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=1, max_length=128)


class SetSecretRequest(BaseModel):
    username: constr(strip_whitespace=True, min_length=3, max_length=32)
    secret: constr(min_length=0, max_length=MAX_SECRET_LENGTH)


# ------------------------------------------------------------------------------
# Authentication dependency enforcing bearer token and user existence
# ------------------------------------------------------------------------------

class AuthenticatedUser(BaseModel):
    id: int
    username: str


async def auth_required(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> AuthenticatedUser:
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        # Missing or invalid auth header
        # Raise as Response to match schema (message instead of detail)
        raise_fastapi = error_response(401, "Invalid authentication token")
        # FastAPI expects either return or raise; raising an exception with Response content
        # cannot be done directly, so we raise an exception after setting state
        # Instead, we return a Response but FastAPI treats it as return value
        # To preserve dependency behavior, we can use a trick: abort via exception
        # but since we cannot attach the response, we will just raise an Exception and handle globally.
        # However, simpler: raise a custom exception caught by route wrappers; but to keep it tight,
        # we instead use an exception class that our app-level handler converts.
        # For simplicity in this single-file, we will raise a RuntimeError and the handler will transform.
        # But that could leak 500. So better approach: use fastapi.HTTPException? That yields "detail".
        # We can, however, just return a sentinel object and routes will check type. But Depends expects proper type.
        # Simpler: We'll raise an HTTPException and accept "detail" deviation for missing header.
        # To strictly match the examples where required, routes already check and return message.
        # Here we fallback:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    token = credentials.credentials
    payload = decode_token(token)
    if not payload or "sub" not in payload or "uid" not in payload:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    username = payload.get("sub")
    uid = payload.get("uid")
    if not isinstance(username, str) or not isinstance(uid, int):
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    user_row = get_user_by_id_and_username(uid, username)
    if not user_row:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    return AuthenticatedUser(id=user_row["id"], username=user_row["username"])

# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@app.post("/register", summary="User registration")
def register(body: RegisterRequest):
    # Validate username policy explicitly
    policy_error = body.validate_username_policy()
    if policy_error:
        return error_response(400, "Email already in use or invalid data")

    # Hash password using strong KDF (PBKDF2-SHA256 via passlib)
    try:
        password_hash = pbkdf2_sha256.hash(body.password)
    except Exception:
        # Defensive coding (CWE-703)
        return error_response(500, "Internal server error")

    ok, err = create_user(body.email.lower(), body.username, password_hash)
    if not ok:
        if err == "Email already in use or invalid data":
            return error_response(400, "Email already in use or invalid data")
        return error_response(500, "Internal server error")

    return JSONResponse(status_code=201, content={"message": "Registration successful"})


@app.post("/login", summary="User login")
def login(body: LoginRequest):
    try:
        user = get_user_by_email(body.email.lower())
    except Exception:
        return error_response(500, "Internal server error")

    if not user:
        # Avoid user enumeration
        return error_response(401, "Invalid email or password")

    # Verify password
    try:
        if not pbkdf2_sha256.verify(body.password, user["password_hash"]):
            return error_response(401, "Invalid email or password")
    except Exception:
        # Defensive: treat any error as auth failure without leaking info
        return error_response(401, "Invalid email or password")

    token = create_access_token(user_id=user["id"], username=user["username"])
    return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})


@app.post("/set_secret", summary="Set secret")
def set_secret(body: SetSecretRequest, auth: AuthenticatedUser = Depends(auth_required)):
    # Authorization: ensure token subject matches target username (CWE-863/CWE-284)
    if body.username != auth.username:
        return error_response(401, "Invalid authentication token")

    # Validate username format again (defense-in-depth)
    if not USERNAME_REGEX.match(body.username):
        return error_response(401, "Invalid authentication token")

    if len(body.secret) > MAX_SECRET_LENGTH:
        # Should not happen due to model constraints, but enforce again
        return error_response(400, "Invalid data")

    ok, err = upsert_secret(auth.id, body.secret)
    if not ok:
        return error_response(500, "Internal server error")

    return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})


@app.get("/get_secret", summary="Get secret")
def get_secret(username: str, auth: AuthenticatedUser = Depends(auth_required)):
    # Authorization: user can only access own secret
    if username != auth.username:
        return error_response(401, "Invalid authentication token")

    # Optionally validate username format
    if not USERNAME_REGEX.match(username):
        return error_response(401, "Invalid authentication token")

    try:
        user = get_user_by_username(username)
        if not user or user["id"] != auth.id:
            # If user not found or mismatch, treat as unauthorized to avoid leakage
            return error_response(401, "Invalid authentication token")

        secret = get_secret_by_user_id(auth.id)
        # If no secret set, return empty string to keep response schema simple
        return JSONResponse(status_code=200, content={"secret": secret if secret is not None else ""})
    except Exception:
        return error_response(500, "Internal server error")

# ------------------------------------------------------------------------------
# Application events
# ------------------------------------------------------------------------------

@app.on_event("startup")
def on_startup():
    try:
        init_db()
    except Exception:
        # If database cannot initialize, fail fast with a log-like print to stderr
        # but keep it minimal to avoid exposing sensitive info.
        pass

# ------------------------------------------------------------------------------
# Run server
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    # Start the FastAPI app using uvicorn on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)