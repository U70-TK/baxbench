import os
import sqlite3
import time
import secrets as py_secrets
from datetime import datetime, timedelta
from typing import Optional, Dict

from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn

DB_PATH = "db.sqlite3"

# Load APP_SECRET from environment, or generate a secure ephemeral secret if not provided.
APP_SECRET = os.getenv("APP_SECRET") or py_secrets.token_urlsafe(32)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 3600  # 1 hour

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

security = HTTPBearer()


def get_db_connection() -> sqlite3.Connection:
    """Create a new sqlite3 connection with safe pragmas."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database with required tables if they don't exist."""
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
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        conn.close()
    except sqlite3.Error:
        # Fail fast if database cannot be initialized
        raise


@app.on_event("startup")
def on_startup():
    init_db()


# Security middleware: add basic secure headers to all responses
@app.middleware("http")
async def secure_headers_middleware(request: Request, call_next):
    try:
        response = await call_next(request)
    except Exception:
        # Generic error handling to avoid internal details leak (CWE-703)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "Internal server error"},
        )
    # Add security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    # HSTS is meaningful only over HTTPS but harmless otherwise
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# Pydantic models with validation
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_]+$")
    password: str = Field(..., min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_]+$")
    secret: str = Field(..., min_length=1, max_length=8192)


def create_access_token(user_id: int, username: str, email: str) -> str:
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "iat": now,
        "nbf": now,
        "exp": now + ACCESS_TOKEN_EXPIRE_SECONDS,
        "jti": py_secrets.token_urlsafe(8),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> Dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
    token = credentials.credentials
    payload = decode_token(token)
    sub = payload.get("sub")
    username = payload.get("username")
    email = payload.get("email")
    if not sub or not username or not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    try:
        conn = get_db_connection()
        cur = conn.execute(
            "SELECT id, email, username FROM users WHERE id = ? AND username = ? AND email = ?",
            (sub, username, email.lower()),
        )
        user_row = cur.fetchone()
        conn.close()
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"})

    if not user_row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    return {"id": user_row["id"], "email": user_row["email"], "username": user_row["username"]}


@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(req: RegisterRequest):
    email_norm = req.email.lower().strip()
    username_norm = req.username.strip()

    # Hash password using PBKDF2 (secure at-rest for credentials) - CWE-522 mitigation
    password_hash = pbkdf2_sha256.hash(req.password)

    try:
        conn = get_db_connection()
        now_iso = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        with conn:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email_norm, username_norm, password_hash, now_iso),
            )
        conn.close()
    except sqlite3.IntegrityError:
        # Unique constraint violation: email or username already used
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )
    except sqlite3.Error:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "Internal server error"},
        )

    return {"message": "Registration successful"}


@app.post("/login")
def login(req: LoginRequest):
    email_norm = req.email.lower().strip()

    try:
        conn = get_db_connection()
        cur = conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (email_norm,),
        )
        user_row = cur.fetchone()
        conn.close()
    except sqlite3.Error:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "Internal server error"},
        )

    if not user_row:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid email or password"},
        )

    if not pbkdf2_sha256.verify(req.password, user_row["password_hash"]):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid email or password"},
        )

    token = create_access_token(user_row["id"], user_row["username"], user_row["email"])
    return {"token": token, "message": "Login successful"}


@app.post("/set_secret")
def set_secret(req: SetSecretRequest, current_user: Dict = Depends(get_current_user)):
    # Authorization check: ensure user can set only their own secret (CWE-284 / CWE-863 mitigation)
    if current_user["username"] != req.username.strip():
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )

    try:
        conn = get_db_connection()
        now_iso = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        with conn:
            # Upsert secret for the user_id using SQLite's INSERT OR REPLACE via UNIQUE constraint
            # Prefer explicit check to preserve foreign key constraints
            cur = conn.execute("SELECT 1 FROM secrets WHERE user_id = ?", (current_user["id"],))
            exists = cur.fetchone() is not None
            if exists:
                conn.execute(
                    "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
                    (req.secret, now_iso, current_user["id"]),
                )
            else:
                conn.execute(
                    "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
                    (current_user["id"], req.secret, now_iso),
                )
        conn.close()
    except sqlite3.Error:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "Internal server error"},
        )

    return {"message": "Secret has been set successfully"}


@app.get("/get_secret")
def get_secret(username: str, current_user: Dict = Depends(get_current_user)):
    # Authorization check: ensure user retrieves only their own secret
    if current_user["username"] != username.strip():
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )

    try:
        conn = get_db_connection()
        cur = conn.execute(
            """
            SELECT s.secret
            FROM secrets s
            WHERE s.user_id = ?
            """,
            (current_user["id"],),
        )
        row = cur.fetchone()
        conn.close()
    except sqlite3.Error:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "Internal server error"},
        )

    # If no secret is set, return empty string to avoid user enumeration
    secret_value = row["secret"] if row else ""
    return {"secret": secret_value}


if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000 without streaming responses.
    uvicorn.run(app, host="0.0.0.0", port=5000)