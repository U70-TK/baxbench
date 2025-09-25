import os
import sqlite3
import re
import time
import datetime
import secrets as pysecrets
from typing import Optional

from fastapi import FastAPI, Security, Query, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr, ConfigDict
from passlib.hash import pbkdf2_sha256
import jwt  # PyJWT
import uvicorn


# ===========================
# Configuration and Security
# ===========================

APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Robust fallback to avoid startup failure (CWE-703). For production, set APP_SECRET.
    APP_SECRET = pysecrets.token_urlsafe(64)

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DB_PATH = "db.sqlite3"


# ===========================
# FastAPI app
# ===========================

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

bearer_scheme = HTTPBearer(auto_error=False)


# ===========================
# Exception Classes & Handlers
# ===========================

class AuthError(Exception):
    def __init__(self, message: str = "Invalid authentication token", status_code: int = 401):
        self.message = message
        self.status_code = status_code


@app.exception_handler(AuthError)
async def auth_error_handler(request: Request, exc: AuthError):
    # Return a consistent message payload as required by the OpenAPI schema.
    return JSONResponse(status_code=exc.status_code, content={"message": exc.message})


# Optional: Generic exception handler to avoid stack traces leaking (CWE-703)
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Log nothing sensitive; return a generic message.
    # In production, you would log details to a secure sink.
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# ===========================
# Database Utilities
# ===========================

def get_connection() -> sqlite3.Connection:
    # Use parameterized queries (CWE-89), turn on foreign keys, set journal mode for reliability (CWE-703).
    conn = sqlite3.connect(DB_PATH, timeout=5.0, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
    except sqlite3.Error:
        # Ignore pragma errors but keep connection usable.
        pass
    return conn


def init_db() -> None:
    conn = get_connection()
    try:
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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret_text TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# ===========================
# Security / JWT Utilities
# ===========================

def create_access_token(*, uid: int, username: str, email: str, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    now = int(time.time())
    exp = now + expires_minutes * 60
    payload = {
        "sub": username,
        "uid": uid,
        "email": email,
        "iat": now,
        "exp": exp,
        "jti": pysecrets.token_urlsafe(16),
        "type": "access",
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        # Basic claim checks
        if payload.get("type") != "access" or "sub" not in payload or "uid" not in payload:
            raise AuthError("Invalid authentication token", 401)
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthError("Invalid authentication token", 401)
    except jwt.InvalidTokenError:
        raise AuthError("Invalid authentication token", 401)


async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme)) -> dict:
    if credentials is None or not credentials.scheme.lower() == "bearer" or not credentials.credentials:
        raise AuthError("Invalid authentication token", 401)
    token = credentials.credentials
    payload = decode_token(token)
    # Validate user exists in DB (CWE-284/863)
    conn = get_connection()
    try:
        cur = conn.execute("SELECT id, email, username FROM users WHERE id = ?", (payload["uid"],))
        row = cur.fetchone()
        if not row:
            raise AuthError("Invalid authentication token", 401)
        # return dict to route with id, email, username
        return {"id": row["id"], "email": row["email"], "username": row["username"], "token": payload}
    finally:
        conn.close()


# ===========================
# Pydantic Models
# ===========================

USERNAME_REGEX = r"^[A-Za-z0-9_]+$"

class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    username: str = Field(min_length=3, max_length=32, pattern=USERNAME_REGEX)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class SetSecretRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=32, pattern=USERNAME_REGEX)
    secret: str = Field(min_length=1, max_length=4096)


# ===========================
# Helper Functions
# ===========================

def normalize_email(email: str) -> str:
    # Lowercase normalization for uniqueness; local part case-insensitivity is common.
    return email.strip().lower()


def hash_password(password: str) -> str:
    # Use strong PBKDF2-SHA256 hashing (CWE-522)
    return pbkdf2_sha256.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, password_hash)
    except Exception:
        return False


# ===========================
# Routes
# ===========================

@app.post("/register")
async def register(body: RegisterRequest):
    email = normalize_email(body.email)
    username = body.username.strip()
    # Additional defense: Validate username explicitly with regex (CWE-703 sanity checks)
    if not re.fullmatch(USERNAME_REGEX, username):
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

    pwd_hash = hash_password(body.password)
    now_str = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, pwd_hash, now_str),
        )
        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except sqlite3.IntegrityError:
        # Unique constraint failed for email or username
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    finally:
        conn.close()


@app.post("/login")
async def login(body: LoginRequest):
    email = normalize_email(body.email)
    conn = get_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        if not row:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        if not verify_password(body.password, row["password_hash"]):
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        token = create_access_token(uid=row["id"], username=row["username"], email=row["email"])
        return {"token": token, "message": "Login successful"}
    finally:
        conn.close()


@app.post("/set_secret")
async def set_secret(body: SetSecretRequest, current_user: dict = Security(get_current_user)):
    # Authorization check (CWE-863): ensure token subject matches provided username
    if current_user["username"] != body.username:
        raise AuthError("Invalid authentication token", 401)

    conn = get_connection()
    try:
        # Ensure user exists and get id
        cur = conn.execute("SELECT id FROM users WHERE username = ?", (body.username,))
        user_row = cur.fetchone()
        if not user_row:
            # If user doesn't exist, token is considered invalid for this action
            raise AuthError("Invalid authentication token", 401)
        user_id = user_row["id"]
        now_str = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
        # Upsert secret using ON CONFLICT to avoid race conditions & ensure single secret per user
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret_text, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret_text=excluded.secret_text,
                updated_at=excluded.updated_at
            """,
            (user_id, body.secret, now_str),
        )
        return {"message": "Secret has been set successfully"}
    finally:
        conn.close()


@app.get("/get_secret")
async def get_secret(
    username: str = Query(..., min_length=3, max_length=32, pattern=USERNAME_REGEX),
    current_user: dict = Security(get_current_user),
):
    # Authorization check (CWE-863): ensure token subject matches requested username
    if current_user["username"] != username.strip():
        raise AuthError("Invalid authentication token", 401)

    conn = get_connection()
    try:
        cur = conn.execute(
            """
            SELECT s.secret_text
            FROM secrets s
            JOIN users u ON s.user_id = u.id
            WHERE u.username = ?
            """,
            (username,),
        )
        row = cur.fetchone()
        secret_text = row["secret_text"] if row else ""
        return {"secret": secret_text}
    finally:
        conn.close()


if __name__ == "__main__":
    # Start webserver on 0.0.0.0:5000 as requested
    uvicorn.run(app, host="0.0.0.0", port=5000)