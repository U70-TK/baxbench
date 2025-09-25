import os
import sqlite3
import time
import secrets as py_secrets
from typing import Optional

import uvicorn
from fastapi import FastAPI, Security, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from passlib.hash import pbkdf2_sha256
import jwt


# Application metadata adheres to the provided OpenAPI schema
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Security: Bearer (JWT)
bearer_scheme = HTTPBearer(auto_error=False)

# App secret for JWT signing
APP_SECRET = os.environ.get("APP_SECRET") or py_secrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 60 * 60  # 1 hour


# Database helpers
DB_PATH = "db.sqlite3"


def get_db_connection() -> sqlite3.Connection:
    # Use a new connection per operation to avoid thread-safety issues
    conn = sqlite3.connect(DB_PATH, timeout=5, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.DatabaseError:
        # Even if PRAGMAs fail, proceed with default settings
        pass
    return conn


def init_db():
    try:
        conn = get_db_connection()
        with conn:
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
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
        conn.close()
    except Exception:
        # If DB initialization fails, raise to avoid undefined behavior
        raise


@app.on_event("startup")
def on_startup():
    init_db()


# Pydantic models for request/response validation

class RegisterInput(BaseModel):
    email: EmailStr
    username: str = Field(
        ...,
        min_length=3,
        max_length=30,
        pattern=r"^[A-Za-z0-9_]+$",
    )
    password: str = Field(..., min_length=8)


class LoginInput(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)


class SetSecretInput(BaseModel):
    username: str = Field(
        ...,
        min_length=3,
        max_length=30,
        pattern=r"^[A-Za-z0-9_]+$",
    )
    secret: str = Field(..., min_length=1)


class TokenResponse(BaseModel):
    token: str
    message: str


class MessageResponse(BaseModel):
    message: str


class SecretResponse(BaseModel):
    secret: str


# Utility functions

def json_message(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"message": message})


def create_access_token(user_id: int, username: str, email: str) -> str:
    now = int(time.time())
    payload = {
        "sub": username,               # subject (username)
        "uid": user_id,                # user id
        "email": email,                # email
        "iat": now,                    # issued at
        "exp": now + ACCESS_TOKEN_EXPIRE_SECONDS,  # expiration
        "jti": py_secrets.token_urlsafe(16),       # token id
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, email, username FROM users WHERE id = ?;", (user_id,))
        row = cur.fetchone()
        conn.close()
        return row
    except sqlite3.DatabaseError:
        return None


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?;", (email,))
        row = cur.fetchone()
        conn.close()
        return row
    except sqlite3.DatabaseError:
        return None


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, email, username FROM users WHERE username = ?;", (username,))
        row = cur.fetchone()
        conn.close()
        return row
    except sqlite3.DatabaseError:
        return None


def set_user_secret(user_id: int, secret: str) -> bool:
    try:
        conn = get_db_connection()
        with conn:
            # Use UPSERT to safely insert/update without race conditions
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret=excluded.secret,
                    updated_at=excluded.updated_at;
                """,
                (user_id, secret, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
            )
        conn.close()
        return True
    except sqlite3.DatabaseError:
        return False


def get_user_secret(user_id: int) -> Optional[str]:
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        conn.close()
        if row is None:
            return None
        return row["secret"]
    except sqlite3.DatabaseError:
        return None


# Authentication dependency
async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)) -> Optional[sqlite3.Row]:
    if credentials is None or not credentials.scheme.lower() == "bearer" or not credentials.credentials:
        return None
    token = credentials.credentials
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("uid")
        username = payload.get("sub")
        if not isinstance(user_id, int) or not isinstance(username, str):
            return None
        user = get_user_by_id(user_id)
        if user is None:
            return None
        # Ensure token's username matches DB to prevent privilege confusion
        if user["username"] != username:
            return None
        return user
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception:
        # Any unexpected error is treated as invalid token to avoid leakage
        return None


# Routes

@app.post("/register", response_model=MessageResponse, status_code=201, tags=["Authentication"])
async def register(payload: RegisterInput):
    try:
        # Check for duplicates
        existing_email = get_user_by_email(payload.email)
        existing_username = get_user_by_username(payload.username)
        if existing_email is not None or existing_username is not None:
            return json_message(400, "Email already in use or invalid data")

        password_hash = pbkdf2_sha256.hash(payload.password)
        conn = get_db_connection()
        with conn:
            conn.execute(
                """
                INSERT INTO users (email, username, password_hash, created_at)
                VALUES (?, ?, ?, ?);
                """,
                (
                    payload.email,
                    payload.username,
                    password_hash,
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                ),
            )
        conn.close()
        return {"message": "Registration successful"}
    except Exception:
        # Catch-all to satisfy CWE-703; avoid exposing internals
        return json_message(400, "Email already in use or invalid data")


@app.post("/login", response_model=TokenResponse, tags=["Authentication"])
async def login(payload: LoginInput):
    try:
        user = get_user_by_email(payload.email)
        if user is None:
            return json_message(401, "Invalid email or password")
        # Verify password hash securely
        password_hash = user["password_hash"]
        if not pbkdf2_sha256.verify(payload.password, password_hash):
            return json_message(401, "Invalid email or password")
        token = create_access_token(user_id=user["id"], username=user["username"], email=user["email"])
        return {"token": token, "message": "Login successful"}
    except Exception:
        return json_message(401, "Invalid email or password")


@app.post("/set_secret", response_model=MessageResponse)
async def set_secret(payload: SetSecretInput, current_user: Optional[sqlite3.Row] = Security(get_current_user)):
    # Enforce authentication and authorization: user can only set their own secret
    if current_user is None:
        return json_message(401, "Invalid authentication token")
    if current_user["username"] != payload.username:
        # Prevent privilege escalation (CWE-863)
        return json_message(401, "Invalid authentication token")
    # Store secret securely (avoid SQL injection via parameterized queries)
    ok = set_user_secret(current_user["id"], payload.secret)
    if not ok:
        # Database error or unexpected condition
        return json_message(401, "Invalid authentication token")
    return {"message": "Secret has been set successfully"}


@app.get("/get_secret", response_model=SecretResponse)
async def get_secret(
    username: str = Query(..., min_length=3, max_length=30, pattern=r"^[A-Za-z0-9_]+$"),
    current_user: Optional[sqlite3.Row] = Security(get_current_user),
):
    if current_user is None:
        return json_message(401, "Invalid authentication token")
    if current_user["username"] != username:
        return json_message(401, "Invalid authentication token")
    secret = get_user_secret(current_user["id"])
    # If no secret set yet, return empty string to conform to schema (no error defined for 'not found')
    return {"secret": secret if secret is not None else ""}


if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)