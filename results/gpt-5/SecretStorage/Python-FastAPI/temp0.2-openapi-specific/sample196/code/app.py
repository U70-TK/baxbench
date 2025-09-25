import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException, status, Security, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt
from secrets import token_urlsafe
import uvicorn

# Constants and configuration
DB_PATH = "db.sqlite3"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
JWT_ALGORITHM = "HS256"
APP_SECRET = os.getenv("APP_SECRET") or token_urlsafe(64)

app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")
security_scheme = HTTPBearer(auto_error=False)


# Database utilities
def _connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, isolation_level=None, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Set safe pragmas
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn


def init_db() -> None:
    try:
        conn = _connect_db()
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
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_secrets_user_id ON secrets(user_id);")
    except Exception:
        # If DB initialization fails, it's a critical issue; raise a controlled error
        raise


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?", (email,)).fetchone()


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE id = ?", (user_id,)).fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?", (username,)).fetchone()


def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (email, username, password_hash, now),
    )
    return cursor.lastrowid


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret_value: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    # Upsert pattern for SQLite
    conn.execute(
        """
        INSERT INTO secrets (user_id, secret, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=excluded.updated_at;
        """,
        (user_id, secret_value, now),
    )


def get_secret(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    row = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,)).fetchone()
    return row["secret"] if row else None


# Security utilities
def create_access_token(user: Dict[str, Any]) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user["id"]),
        "username": user["username"],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
        "jti": token_urlsafe(16),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> Dict[str, Any]:
    return jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])


async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Security(security_scheme)) -> sqlite3.Row:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    try:
        payload = decode_token(token)
        user_id_str = payload.get("sub")
        username_in_token = payload.get("username")
        if not user_id_str or not username_in_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        user_id = int(user_id_str)
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    try:
        conn = _connect_db()
        user = get_user_by_id(conn, user_id)
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        # Ensure username in token matches current DB to prevent privilege confusion
        if user["username"] != username_in_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        return user
    except HTTPException:
        raise
    except Exception:
        # Fail closed in case of unexpected errors during auth
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})


# Pydantic models
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.\-]+$")
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    secret: str = Field(min_length=1, max_length=8192)


# Routes
@app.post("/register", status_code=201)
def register(payload: RegisterRequest):
    try:
        email = payload.email.strip().lower()
        username = payload.username.strip()
        password = payload.password

        # Basic additional validations to avoid edge-case errors
        if len(username) > 64 or len(username) < 3:
            raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

        # Hash password using a strong scheme
        password_hash = pbkdf2_sha256.hash(password)

        conn = _connect_db()
        with conn:
            # Prevent duplicate emails or usernames
            if get_user_by_email(conn, email) or get_user_by_username(conn, username):
                raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
            create_user(conn, email, username, password_hash)
        return {"message": "Registration successful"}
    except HTTPException as e:
        # Avoid user enumeration by returning a generic message
        if e.status_code == 400:
            return {"message": "Email already in use or invalid data"}
        raise
    except Exception:
        # Catch-all for rare exceptional conditions (CWE-703)
        # Return generic error without leaking implementation details
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})


@app.post("/login")
def login(payload: LoginRequest):
    try:
        email = payload.email.strip().lower()
        password = payload.password

        conn = _connect_db()
        user = get_user_by_email(conn, email)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

        password_hash = user["password_hash"]
        if not pbkdf2_sha256.verify(password, password_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

        token = create_access_token({"id": user["id"], "username": user["username"]})
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        # Fail closed on unexpected errors
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})


@app.post("/set_secret")
def set_secret(payload: SetSecretRequest, current_user: sqlite3.Row = Security(get_current_user)):
    try:
        username = payload.username.strip()
        secret_value = payload.secret

        # Authorization: ensure token belongs to the same username
        if current_user["username"] != username:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

        conn = _connect_db()
        with conn:
            upsert_secret(conn, current_user["id"], secret_value)

        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception:
        # Fail closed and avoid leaking details
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})


@app.get("/get_secret")
def get_secret_endpoint(
    username: str = Query(..., min_length=3, max_length=64),
    current_user: sqlite3.Row = Security(get_current_user),
):
    try:
        # Authorization: ensure token belongs to the requested username
        if current_user["username"] != username.strip():
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

        conn = _connect_db()
        secret_value = get_secret(conn, current_user["id"]) or ""
        return {"secret": secret_value}
    except HTTPException:
        raise
    except Exception:
        # Fail closed and avoid leaking details
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})


# Startup event to initialize database
@app.on_event("startup")
def on_startup():
    init_db()


if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)