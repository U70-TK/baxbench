import os
import sqlite3
import secrets as pysecrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Request, status, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, field_validator
from passlib.hash import pbkdf2_sha256
import jwt

# ------------------------------------------------------------
# Configuration and Security
# ------------------------------------------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secret-storage")

APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Generate an ephemeral secret if not provided (tokens won't survive restarts)
    APP_SECRET = pysecrets.token_urlsafe(64)
    logger.warning("APP_SECRET not set; generated an ephemeral secret. Set APP_SECRET env var for persistent tokens.")

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour


def create_access_token(*, subject: str, email: str, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=expires_minutes)
    payload = {
        "sub": subject,
        "email": email,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": pysecrets.token_urlsafe(16),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})


# ------------------------------------------------------------
# Database
# ------------------------------------------------------------

DB_PATH = "db.sqlite3"


def get_connection() -> sqlite3.Connection:
    # Create a new connection per usage to avoid cross-thread issues
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Safe pragmas
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.Error:
        pass
    return conn


def init_db() -> None:
    conn = get_connection()
    try:
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
    finally:
        conn.close()


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    conn = get_connection()
    try:
        cur = conn.execute("SELECT * FROM users WHERE email = ?;", (email,))
        return cur.fetchone()
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_connection()
    try:
        cur = conn.execute("SELECT * FROM users WHERE username = ?;", (username,))
        return cur.fetchone()
    finally:
        conn.close()


def create_user(email: str, username: str, password_hash: str) -> bool:
    conn = get_connection()
    try:
        with conn:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
                (email, username, password_hash, datetime.now(timezone.utc).isoformat()),
            )
        return True
    except sqlite3.IntegrityError:
        return False
    except sqlite3.Error:
        # Unexpected DB error
        raise
    finally:
        conn.close()


def upsert_secret_for_user(username: str, secret_text: str) -> bool:
    user = get_user_by_username(username)
    if not user:
        return False
    user_id = user["id"]
    conn = get_connection()
    try:
        with conn:
            # Try update first
            cur = conn.execute(
                "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?;",
                (secret_text, datetime.now(timezone.utc).isoformat(), user_id),
            )
            if cur.rowcount == 0:
                # Insert if not exists
                conn.execute(
                    "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?);",
                    (user_id, secret_text, datetime.now(timezone.utc).isoformat()),
                )
        return True
    except sqlite3.Error:
        raise
    finally:
        conn.close()


def get_secret_for_username(username: str) -> Optional[str]:
    user = get_user_by_username(username)
    if not user:
        return None
    user_id = user["id"]
    conn = get_connection()
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        if row:
            return row["secret"]
        return ""
    finally:
        conn.close()


# ------------------------------------------------------------
# Models
# ------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def username_rules(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Username cannot be empty")
        if len(v) > 64:
            raise ValueError("Username too long")
        return v

    @field_validator("password")
    @classmethod
    def password_rules(cls, v: str) -> str:
        if len(v) < 6:
            raise ValueError("Password must be at least 6 characters long")
        if len(v) > 256:
            raise ValueError("Password too long")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class SetSecretRequest(BaseModel):
    username: str
    secret: str

    @field_validator("username")
    @classmethod
    def username_trim(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Username cannot be empty")
        return v

    @field_validator("secret")
    @classmethod
    def secret_rules(cls, v: str) -> str:
        if v is None:
            raise ValueError("Secret cannot be null")
        return v


# ------------------------------------------------------------
# FastAPI App and Security Dependency
# ------------------------------------------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    contact={"name": "Secret Storage"},
)

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_claims(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)) -> dict:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    claims = decode_token(token)
    return claims


# ------------------------------------------------------------
# Exception Handlers
# ------------------------------------------------------------

@app.exception_handler(sqlite3.Error)
async def sqlite_error_handler(request: Request, exc: sqlite3.Error):
    # Log internal DB errors, return generic message
    logger.exception("Database error occurred")
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error occurred")
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# ------------------------------------------------------------
# Startup
# ------------------------------------------------------------

@app.on_event("startup")
def on_startup():
    init_db()


# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------

@app.post("/register", status_code=201)
async def register(payload: RegisterRequest):
    try:
        email = payload.email.strip().lower()
        username = payload.username.strip()
        password_hash = pbkdf2_sha256.hash(payload.password)

        # Ensure uniqueness
        if get_user_by_email(email) or get_user_by_username(username):
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        created = create_user(email=email, username=username, password_hash=password_hash)
        if not created:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except Exception:
        # Capture unforeseen issues gracefully
        logger.exception("Error during registration")
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})


@app.post("/login")
async def login(payload: LoginRequest):
    try:
        email = payload.email.strip().lower()
        user = get_user_by_email(email)
        if not user:
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
        password_hash = user["password_hash"]
        if not pbkdf2_sha256.verify(payload.password, password_hash):
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
        token = create_access_token(subject=user["username"], email=user["email"])
        return {"token": token, "message": "Login successful"}
    except HTTPException as he:
        raise he
    except Exception:
        logger.exception("Error during login")
        raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})


@app.post("/set_secret")
async def set_secret(payload: SetSecretRequest, claims: dict = Depends(get_current_claims)):
    try:
        token_username = claims.get("sub")
        if not token_username or token_username != payload.username.strip():
            # Authorization mismatch - treat as invalid token per spec's 401 messaging
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

        # Ensure user exists
        user = get_user_by_username(payload.username.strip())
        if not user:
            # For security, don't leak existence; treat as invalid token
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

        success = upsert_secret_for_user(payload.username.strip(), payload.secret)
        if not success:
            # If failed due to user not found or DB error
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        return {"message": "Secret has been set successfully"}
    except HTTPException as he:
        raise he
    except Exception:
        logger.exception("Error while setting secret")
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})


@app.get("/get_secret")
async def get_secret(username: str = Query(...), claims: dict = Depends(get_current_claims)):
    try:
        token_username = claims.get("sub")
        if not token_username or token_username != username.strip():
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

        # Ensure user exists
        user = get_user_by_username(username.strip())
        if not user:
            # For security, treat as invalid token or return empty secret; spec expects 401 for unauthorized.
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

        secret_value = get_secret_for_username(username.strip())
        if secret_value is None:
            # user not found -> unauthorized
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        # If no secret set yet, return empty string as secret
        return {"secret": secret_value}
    except HTTPException as he:
        raise he
    except Exception:
        logger.exception("Error while retrieving secret")
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})


# ------------------------------------------------------------
# Run server
# ------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)