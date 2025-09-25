import os
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Optional, Tuple

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi import status, Body, Query
from pydantic import BaseModel, EmailStr, Field, constr
from passlib.context import CryptContext
import jwt

# ----------------------------
# Configuration and Security
# ----------------------------

APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Generate an ephemeral secret to allow the app to run; in production, set APP_SECRET.
    APP_SECRET = os.urandom(32).hex()

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 3600  # 1 hour

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

DB_PATH = "db.sqlite3"


# ----------------------------
# Database Utilities
# ----------------------------

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, isolation_level=None, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    # Secure PRAGMAs: enforce foreign keys; WAL for concurrency
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.Error:
        # Ignore pragma errors gracefully
        pass
    return conn


def init_db() -> None:
    conn = get_db_connection()
    try:
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
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
    finally:
        conn.close()


# ----------------------------
# Models
# ----------------------------

UsernameStr = constr(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")

class RegisterRequest(BaseModel):
    email: EmailStr
    username: UsernameStr
    password: constr(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=8, max_length=128)


class SetSecretRequest(BaseModel):
    username: UsernameStr
    secret: constr(min_length=1, max_length=4096)


# ----------------------------
# Helpers
# ----------------------------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(plain_password, password_hash)
    except Exception:
        # Any unexpected verification error should be treated as failure to avoid CWE-703 surprises.
        return False


def create_access_token(user_row: sqlite3.Row) -> str:
    now = int(time.time())
    payload = {
        "sub": str(user_row["id"]),
        "username": user_row["username"],
        "email": user_row["email"],
        "iat": now,
        "exp": now + ACCESS_TOKEN_EXPIRE_SECONDS,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception:
        return None


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    return row


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    return row


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    return row


def upsert_secret_for_user(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    # Try update; if no row, insert to avoid needing newer SQLite features.
    cur = conn.execute("UPDATE secrets SET secret = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?", (secret, user_id))
    if cur.rowcount == 0:
        conn.execute("INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)", (user_id, secret))


def get_secret_for_user(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if row is None:
        return None
    return row["secret"]


def extract_bearer_token(request: Request) -> Optional[str]:
    auth = request.headers.get("Authorization")
    if not auth or not isinstance(auth, str):
        return None
    if not auth.startswith("Bearer "):
        return None
    return auth[len("Bearer "):].strip()


def authorize_request_for_username(request: Request, username: str) -> Tuple[bool, Optional[sqlite3.Row]]:
    """
    Validates bearer token and ensures the token subject matches the provided username.
    Returns (authorized, user_row).
    """
    token = extract_bearer_token(request)
    if not token:
        return (False, None)
    payload = decode_access_token(token)
    if not payload:
        return (False, None)
    sub = payload.get("sub")
    token_username = payload.get("username")
    if not sub or not token_username or token_username != username:
        return (False, None)
    try:
        user_id = int(sub)
    except Exception:
        return (False, None)
    conn = get_db_connection()
    try:
        user_row = get_user_by_id(conn, user_id)
        if not user_row:
            return (False, None)
        # Ensure username in DB still matches the token to prevent stale token mapping (CWE-863).
        if user_row["username"] != username:
            return (False, None)
        return (True, user_row)
    finally:
        conn.close()


# ----------------------------
# FastAPI App and Routes
# ----------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    openapi_version="3.0.3",
)

@app.on_event("startup")
def on_startup():
    init_db()


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Generic, sanitized error response to avoid leaking details (CWE-703)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "Internal server error"},
    )


@app.post("/register", status_code=201)
async def register(payload: RegisterRequest):
    conn = get_db_connection()
    try:
        # Validate uniqueness
        existing_email = get_user_by_email(conn, payload.email)
        existing_username = get_user_by_username(conn, payload.username)
        if existing_email or existing_username:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )
        password_hash = hash_password(payload.password)
        try:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (payload.email, payload.username, password_hash, datetime.utcnow()),
            )
        except sqlite3.IntegrityError:
            # Catch race condition or constraint violation (CWE-703)
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )
        return {"message": "Registration successful"}
    finally:
        conn.close()


@app.post("/login")
async def login(payload: LoginRequest):
    conn = get_db_connection()
    try:
        user_row = get_user_by_email(conn, payload.email)
        if not user_row:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
            )
        if not verify_password(payload.password, user_row["password_hash"]):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
            )
        token = create_access_token(user_row)
        return {"token": token, "message": "Login successful"}
    finally:
        conn.close()


@app.post("/set_secret")
async def set_secret(request: Request, payload: SetSecretRequest):
    # Authorization: must match username in payload (CWE-284, CWE-863)
    authorized, user_row = authorize_request_for_username(request, payload.username)
    if not authorized or not user_row:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )
    conn = get_db_connection()
    try:
        upsert_secret_for_user(conn, user_row["id"], payload.secret)
        return {"message": "Secret has been set successfully"}
    finally:
        conn.close()


@app.get("/get_secret")
async def get_secret(request: Request, username: UsernameStr = Query(..., examples=["user1"])):
    # Authorization: must match requested username (CWE-284, CWE-863)
    authorized, user_row = authorize_request_for_username(request, username)
    if not authorized or not user_row:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )
    conn = get_db_connection()
    try:
        secret_value = get_secret_for_user(conn, user_row["id"])
        if secret_value is None:
            # If no secret set, return empty string to satisfy schema
            secret_value = ""
        return {"secret": secret_value}
    finally:
        conn.close()


if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000 without streaming responses
    uvicorn.run(app, host="0.0.0.0", port=5000)