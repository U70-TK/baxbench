import os
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, status, Security, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, ValidationError
from email_validator import validate_email, EmailNotValidError
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn

# ----------------------------
# Configuration & Security
# ----------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secret-storage")

APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET or len(APP_SECRET) < 16:
    # Fallback to a strong random secret if not provided. In production, APP_SECRET should be set.
    APP_SECRET = os.environ.get("APP_SECRET", "")
    if not APP_SECRET:
        import secrets as pysecrets

        APP_SECRET = pysecrets.token_urlsafe(64)
        logger.warning("APP_SECRET not provided; generated a temporary secret. Set APP_SECRET in environment for stable tokens.")

JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DB_PATH = "db.sqlite3"


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.Error:
        # Even if PRAGMA fails, we proceed; not critical
        pass
    return conn


def init_db():
    conn = get_db()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER UNIQUE NOT NULL,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
    except sqlite3.Error as e:
        logger.error("Database initialization error: %s", e)
        raise
    finally:
        conn.close()


# ----------------------------
# Models
# ----------------------------

class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=254)
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=8, max_length=128)


class RegisterResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=254)
    password: str = Field(..., min_length=8, max_length=128)


class LoginResponse(BaseModel):
    token: str
    message: str


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    secret: str = Field(..., min_length=1, max_length=8192)


class SetSecretResponse(BaseModel):
    message: str


class GetSecretResponse(BaseModel):
    secret: str


# ----------------------------
# Auth Utilities
# ----------------------------

http_bearer = HTTPBearer(auto_error=False)


def create_access_token(user_id: int, username: str, email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "uid": user_id,
        "email": email,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
        "iss": "secret-storage-app",
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALG)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALG], options={"require": ["exp", "iat", "nbf"]})
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})


def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Security(http_bearer)) -> dict:
    if credentials is None or not credentials.scheme.lower() == "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    payload = decode_token(token)
    # Verify that user exists
    conn = get_db()
    try:
        cur = conn.execute("SELECT id, email, username FROM users WHERE id = ?", (payload.get("uid"),))
        row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        # Defensive check: ensure username matches
        if row["username"] != payload.get("sub"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        return {"id": row["id"], "email": row["email"], "username": row["username"]}
    except sqlite3.Error:
        # If DB fails during auth, treat as unauthorized to avoid information leaks
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    finally:
        conn.close()


# ----------------------------
# Application
# ----------------------------

app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")


@app.on_event("startup")
def on_startup():
    try:
        init_db()
    except Exception as e:
        logger.error("Startup failed: %s", e)
        # Fatal initialization error
        raise


# ----------------------------
# Routes
# ----------------------------

@app.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED, tags=["Authentication"])
def register(req: RegisterRequest):
    try:
        # Validate email strictly
        try:
            v = validate_email(req.email)
            email_normalized = v.email
        except EmailNotValidError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})

        username = req.username.strip()
        # Optional: restrict allowed characters for username to mitigate ambiguous inputs
        allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        if not set(username) <= allowed_chars:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})

        # Hash password securely
        password_hash = pbkdf2_sha256.hash(req.password)

        conn = get_db()
        try:
            # Enforce uniqueness via DB constraints (and consistent message on violation)
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email_normalized, username, password_hash, now),
            )
            return {"message": "Registration successful"}
        except sqlite3.IntegrityError:
            # Email or username already exists
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
        finally:
            conn.close()
    except HTTPException:
        # Propagate known errors
        raise
    except Exception:
        # Catch-all to avoid leaking internal errors (CWE-703)
        logger.exception("Unhandled error in /register")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})


@app.post("/login", response_model=LoginResponse, tags=["Authentication"])
def login(req: LoginRequest):
    try:
        # Normalize email
        try:
            v = validate_email(req.email)
            email_normalized = v.email
        except EmailNotValidError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

        conn = get_db()
        try:
            cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email_normalized,))
            user = cur.fetchone()
            if user is None:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

            if not pbkdf2_sha256.verify(req.password, user["password_hash"]):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

            token = create_access_token(user_id=user["id"], username=user["username"], email=user["email"])
            return {"token": token, "message": "Login successful"}
        finally:
            conn.close()
    except HTTPException:
        raise
    except Exception:
        logger.exception("Unhandled error in /login")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})


@app.post("/set_secret", response_model=SetSecretResponse)
def set_secret(req: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    try:
        # Authorization: ensure user can only set their own secret (CWE-284 / CWE-863)
        if req.username.strip() != current_user["username"]:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

        conn = get_db()
        try:
            now = datetime.now(timezone.utc).isoformat()
            # Upsert secret atomically
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=excluded.updated_at
                """,
                (current_user["id"], req.secret, now),
            )
            return {"message": "Secret has been set successfully"}
        finally:
            conn.close()
    except HTTPException:
        raise
    except Exception:
        logger.exception("Unhandled error in /set_secret")
        # For unexpected failures during setting secret, avoid leaking info
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})


@app.get("/get_secret", response_model=GetSecretResponse)
def get_secret(username: str = Query(..., min_length=3, max_length=64), current_user: dict = Depends(get_current_user)):
    try:
        # Authorization: ensure token owner matches requested username (CWE-284 / CWE-863)
        if username.strip() != current_user["username"]:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

        conn = get_db()
        try:
            cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (current_user["id"],))
            row = cur.fetchone()
            secret_text = row["secret"] if row is not None else ""
            return {"secret": secret_text}
        finally:
            conn.close()
    except HTTPException:
        raise
    except Exception:
        logger.exception("Unhandled error in /get_secret")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})


# ----------------------------
# Global exception handler (CWE-703)
# ----------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.exception("Unhandled server error: %s", exc)
    # Avoid leaking internal details; provide a generic message.
    return fastapi_json_response(status_code=500, content={"message": "Internal server error"})


# Helper to create JSON Response without importing Response explicitly
from fastapi.responses import JSONResponse


def fastapi_json_response(status_code: int, content: dict) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=content)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)