import os
import re
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr, ValidationError
from passlib.hash import pbkdf2_sha256
import jwt  # PyJWT


DB_PATH = "db.sqlite3"

# Application secret for JWT
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to a random secret if none provided; warn in logs.
    # In production, always set APP_SECRET!
    import secrets as _secrets

    APP_SECRET = _secrets.token_urlsafe(64)


# FastAPI app
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

security_scheme = HTTPBearer(auto_error=False)


# Database utility functions
def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db():
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
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
    finally:
        conn.close()


init_db()


# Models
USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,32}$")


class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=256)

    def normalize(self):
        self.email = self.email.lower().strip()
        self.username = self.username.strip()


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)

    def normalize(self):
        self.email = self.email.lower().strip()


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    secret: str = Field(min_length=0, max_length=4096)

    def normalize(self):
        self.username = self.username.strip()


# Helpers: security
def hash_password(password: str) -> str:
    return pbkdf2_sha256.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, password_hash)
    except Exception:
        return False


def create_access_token(username: str, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(tz=timezone.utc)
    exp = now + (expires_delta if expires_delta else timedelta(hours=1))
    payload = {
        "sub": username,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "nbf": int(now.timestamp()),
        "iss": "secret-storage-app",
    }
    token = jwt.encode(payload, APP_SECRET, algorithm="HS256")
    return token


def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=["HS256"], options={"require": ["exp", "iat", "nbf"]})
        return payload
    except jwt.PyJWTError:
        return None


async def get_current_username(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme)) -> Optional[str]:
    if credentials is None or credentials.scheme.lower() != "bearer":
        return None
    token = credentials.credentials
    payload = decode_access_token(token)
    if not payload:
        return None
    username = payload.get("sub")
    if not username or not isinstance(username, str):
        return None
    return username


# Data access functions
def user_exists_by_email(conn: sqlite3.Connection, email: str) -> bool:
    cur = conn.execute("SELECT 1 FROM users WHERE email = ?;", (email,))
    return cur.fetchone() is not None


def user_exists_by_username(conn: sqlite3.Connection, username: str) -> bool:
    cur = conn.execute("SELECT 1 FROM users WHERE username = ?;", (username,))
    return cur.fetchone() is not None


def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> int:
    cur = conn.execute(
        "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?);",
        (email, username, password_hash),
    )
    return cur.lastrowid


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?;", (email,))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?;", (username,))
    return cur.fetchone()


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret_value: str) -> None:
    # Use UPSERT to insert or update the secret atomically
    conn.execute(
        """
        INSERT INTO secrets (user_id, secret, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=CURRENT_TIMESTAMP;
        """,
        (user_id, secret_value),
    )


def get_secret_by_user_id(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
    row = cur.fetchone()
    if row is None:
        return None
    return row["secret"]


# Standardized responses for errors matching the spec
def unauthorized_response():
    return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})


def bad_request_response():
    return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})


# Routes
@app.post("/register", include_in_schema=True)
async def register(payload: RegisterRequest):
    try:
        payload.normalize()
        # Validate username pattern
        if not USERNAME_REGEX.fullmatch(payload.username):
            return bad_request_response()
        # Hash password
        pwd_hash = hash_password(payload.password)
        # Store user
        conn = get_db_connection()
        try:
            # Ensure uniqueness
            if user_exists_by_email(conn, payload.email) or user_exists_by_username(conn, payload.username):
                return bad_request_response()
            create_user(conn, payload.email, payload.username, pwd_hash)
            return JSONResponse(status_code=201, content={"message": "Registration successful"})
        finally:
            conn.close()
    except ValidationError:
        return bad_request_response()
    except Exception:
        # Avoid leaking details; handle exceptional conditions properly
        return bad_request_response()


@app.post("/login", include_in_schema=True)
async def login(payload: LoginRequest):
    try:
        payload.normalize()
        conn = get_db_connection()
        try:
            user = get_user_by_email(conn, payload.email)
            if not user:
                return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
            if not verify_password(payload.password, user["password_hash"]):
                return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
            token = create_access_token(username=user["username"])
            return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})
        finally:
            conn.close()
    except Exception:
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})


@app.post("/set_secret", include_in_schema=True)
async def set_secret(request: Request, payload: SetSecretRequest, current_username: Optional[str] = Depends(get_current_username)):
    try:
        if current_username is None:
            return unauthorized_response()
        payload.normalize()
        if not USERNAME_REGEX.fullmatch(payload.username):
            return unauthorized_response()  # Do not leak details; treat as auth failure

        # Ensure the token subject matches the target username
        if payload.username != current_username:
            return unauthorized_response()

        conn = get_db_connection()
        try:
            user = get_user_by_username(conn, current_username)
            if not user:
                # Token subject not found; treat as invalid token
                return unauthorized_response()
            upsert_secret(conn, user["id"], payload.secret)
            return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})
        finally:
            conn.close()
    except Exception:
        # Handle unexpected exceptions without leaking internals
        return unauthorized_response()


@app.get("/get_secret", include_in_schema=True)
async def get_secret(username: str, current_username: Optional[str] = Depends(get_current_username)):
    try:
        if current_username is None:
            return unauthorized_response()
        username = (username or "").strip()
        if not USERNAME_REGEX.fullmatch(username):
            return unauthorized_response()
        if username != current_username:
            return unauthorized_response()

        conn = get_db_connection()
        try:
            user = get_user_by_username(conn, current_username)
            if not user:
                return unauthorized_response()
            secret_value = get_secret_by_user_id(conn, user["id"])
            if secret_value is None:
                secret_value = ""
            return JSONResponse(status_code=200, content={"secret": secret_value})
        finally:
            conn.close()
    except Exception:
        return unauthorized_response()


# Ensure the server starts on 0.0.0.0:5000
if __name__ == "__main__":
    # Uvicorn server
    uvicorn.run(app, host="0.0.0.0", port=5000)