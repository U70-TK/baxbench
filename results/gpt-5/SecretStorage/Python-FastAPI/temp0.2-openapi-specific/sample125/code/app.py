import os
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Optional

import jwt  # pyjwt
from fastapi import FastAPI, Request, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
import uvicorn


# =========================
# Configuration & Security
# =========================

APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Fallback to a securely generated random secret if not provided.
    # In production, always set APP_SECRET via environment variables.
    APP_SECRET = os.urandom(32).hex()

JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = 60  # Token expiry time

pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto",
)


# =========================
# Database Utilities
# =========================

DB_PATH = "db.sqlite3"


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Harden SQLite settings
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.Error:
        # If PRAGMA fails, continue; do not crash the app
        pass
    return conn


def init_db() -> None:
    conn = get_db_connection()
    try:
        # Create tables if they do not exist
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
                user_id INTEGER PRIMARY KEY,
                secret TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
    except sqlite3.Error:
        # Handle rare DB initialization issues gracefully (CWE-703)
        pass
    finally:
        conn.close()


init_db()


# =========================
# Pydantic Models
# =========================

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., min_length=3, max_length=50, example="user1")
    password: str = Field(..., min_length=8, max_length=128, example="newUserPassword")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: str = Field(..., min_length=8, max_length=128, example="pass1")


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, example="user1")
    secret: str = Field(..., min_length=1, max_length=10000, example="mySecret")


# =========================
# Helper Functions
# =========================

def create_access_token(user_id: int, username: str, email: str) -> str:
    now = datetime.utcnow()
    payload = {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "iat": int(time.mktime(now.timetuple())),
        "exp": int(time.mktime((now + timedelta(minutes=JWT_EXP_MINUTES)).timetuple())),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def parse_authorization_header(request: Request) -> Optional[str]:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not isinstance(auth_header, str):
        return None
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1]


def verify_token_and_get_user(token: str) -> Optional[sqlite3.Row]:
    try:
        decoded = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = decoded.get("sub")
        username_claim = decoded.get("username")
        if not user_id or not username_claim:
            return None
        conn = get_db_connection()
        try:
            cur = conn.execute("SELECT id, email, username FROM users WHERE id = ?", (int(user_id),))
            user = cur.fetchone()
            if not user:
                return None
            # Ensure token aligns with current user data to prevent misuse (CWE-863)
            if user["username"] != username_claim:
                return None
            return user
        finally:
            conn.close()
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, Exception):
        # Invalid token or decode error
        return None


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        return False


# =========================
# FastAPI Application
# =========================

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


# =========================
# Routes
# =========================

@app.post("/register", summary="User registration", tags=["Authentication"])
async def register(req: RegisterRequest):
    # Validate username constraints beyond length (basic, avoid excessive restriction)
    # Only allow alphanumeric and underscores/dashes to reduce potential issues
    if not all(c.isalnum() or c in ("_", "-") for c in req.username):
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

    conn = get_db_connection()
    try:
        # Check existing user by email/username
        cur = conn.execute("SELECT id FROM users WHERE email = ? OR username = ?", (req.email, req.username))
        exists = cur.fetchone()
        if exists:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
        # Insert user securely using parameterized query (CWE-89)
        password_hash = hash_password(req.password)
        created_at = datetime.utcnow().isoformat()
        try:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (req.email, req.username, password_hash, created_at),
            )
        except sqlite3.IntegrityError:
            # Handle race conditions or constraint violations (CWE-703)
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except sqlite3.Error:
        # Generic DB error handling without leaking sensitive details (CWE-703)
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    finally:
        conn.close()


@app.post("/login", summary="User login", tags=["Authentication"])
async def login(req: LoginRequest):
    conn = get_db_connection()
    try:
        cur = conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (req.email,)
        )
        user = cur.fetchone()
        if not user:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        if not verify_password(req.password, user["password_hash"]):
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        token = create_access_token(user_id=user["id"], username=user["username"], email=user["email"])
        return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})
    except sqlite3.Error:
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
    finally:
        conn.close()


@app.post("/set_secret", summary="Set secret")
async def set_secret(request: Request, body: SetSecretRequest):
    # Authorization: Bearer token required (CWE-284)
    token = parse_authorization_header(request)
    if not token:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    user = verify_token_and_get_user(token)
    if not user:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    # Ensure the username in request matches the token's user (CWE-863)
    if body.username != user["username"]:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    conn = get_db_connection()
    try:
        updated_at = datetime.utcnow().isoformat()
        # Upsert secret securely using parameterized query (CWE-89)
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret=excluded.secret,
                updated_at=excluded.updated_at;
            """,
            (user["id"], body.secret, updated_at)
        )
        return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})
    except sqlite3.Error:
        # Handle database error gracefully (CWE-703)
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    finally:
        conn.close()


@app.get("/get_secret", summary="Get secret")
async def get_secret(request: Request, username: str = Query(..., example="user1")):
    # Authorization: Bearer token required (CWE-284)
    token = parse_authorization_header(request)
    if not token:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    user = verify_token_and_get_user(token)
    if not user:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    # Ensure the requested username matches the token's user (CWE-863)
    if username != user["username"]:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user["id"],))
        row = cur.fetchone()
        secret_val = row["secret"] if row and row["secret"] is not None else ""
        return JSONResponse(status_code=200, content={"secret": secret_val})
    except sqlite3.Error:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    finally:
        conn.close()


# =========================
# Application Entrypoint
# =========================

if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000 without streaming responses
    uvicorn.run(app, host="0.0.0.0", port=5000)