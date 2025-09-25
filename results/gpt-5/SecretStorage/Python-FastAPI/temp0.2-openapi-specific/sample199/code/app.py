import os
import re
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Depends, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, field_validator
from jose import JWTError  # imported but not used; using pyjwt instead
import jwt  # PyJWT
from passlib.hash import pbkdf2_sha256
from starlette.middleware.base import BaseHTTPMiddleware

# ------------------------------------------------------------
# Configuration and Logging
# ------------------------------------------------------------
APP_NAME = "Secret Storage"
DATABASE_PATH = "db.sqlite3"
JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = 60

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
)
logger = logging.getLogger(APP_NAME)

APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to a random secret for runtime. Note: tokens won't persist/reuse across restarts without APP_SECRET.
    # This is acceptable for development; production should always supply APP_SECRET.
    import secrets as _secrets

    APP_SECRET = _secrets.token_urlsafe(64)
    logger.warning("APP_SECRET not set. Generated a temporary secret key for this process.")


# ------------------------------------------------------------
# Database helpers
# ------------------------------------------------------------
def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Harden SQLite settings
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def init_db() -> None:
    try:
        conn = get_connection()
        with conn:
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
                    secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """
            )
    except sqlite3.Error as e:
        logger.exception("Failed to initialize the database: %s", e)
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ------------------------------------------------------------
# Pydantic models with validation
# ------------------------------------------------------------
USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,30}$")


class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=30)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not USERNAME_REGEX.fullmatch(v):
            raise ValueError("Username must be 3-30 characters long and contain only letters, numbers, or underscore")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=30)
    secret: str = Field(min_length=1, max_length=4096)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not USERNAME_REGEX.fullmatch(v):
            raise ValueError("Invalid username")
        return v


# ------------------------------------------------------------
# Utility functions (auth, hashing)
# ------------------------------------------------------------
def hash_password(password: str) -> str:
    # PBKDF2-SHA256 with reasonable defaults provided by passlib
    return pbkdf2_sha256.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, password_hash)
    except Exception:
        # In case of corrupted hash, treat as invalid
        return False


def create_jwt_token(user_id: int, username: str, email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXP_MINUTES)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_jwt_token(token: str) -> Optional[dict]:
    try:
        decoded = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return decoded
    except jwt.PyJWTError:
        return None


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    conn = get_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        return row
    except sqlite3.Error as e:
        logger.exception("DB error in get_user_by_email: %s", e)
        raise
    finally:
        conn.close()


def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    conn = get_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        return row
    except sqlite3.Error as e:
        logger.exception("DB error in get_user_by_id: %s", e)
        raise
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        return row
    except sqlite3.Error as e:
        logger.exception("DB error in get_user_by_username: %s", e)
        raise
    finally:
        conn.close()


def upsert_secret(user_id: int, secret_text: str) -> None:
    conn = get_connection()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret=excluded.secret,
                    updated_at=excluded.updated_at
                """,
                (user_id, secret_text, datetime.now(timezone.utc).isoformat()),
            )
    except sqlite3.Error as e:
        logger.exception("DB error in upsert_secret: %s", e)
        raise
    finally:
        conn.close()


def get_secret_by_user_id(user_id: int) -> Optional[str]:
    conn = get_connection()
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        if row:
            return row["secret"]
        return None
    except sqlite3.Error as e:
        logger.exception("DB error in get_secret_by_user_id: %s", e)
        raise
    finally:
        conn.close()


# ------------------------------------------------------------
# FastAPI app and middleware
# ------------------------------------------------------------
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # Basic hardening headers
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        return response


app.add_middleware(SecurityHeadersMiddleware)


@app.on_event("startup")
def on_startup():
    try:
        init_db()
    except Exception as e:
        logger.exception("Failed during startup DB initialization: %s", e)
        raise


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception: %s", exc)
    return JSONResponse(status_code=500, content={"message": "Internal Server Error"})


# ------------------------------------------------------------
# Authentication dependency
# ------------------------------------------------------------
def get_bearer_token_from_header(request: Request) -> Optional[str]:
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1]


async def require_auth(request: Request) -> dict:
    token = get_bearer_token_from_header(request)
    if not token:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    claims = decode_jwt_token(token)
    if not claims:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    user_id_str = claims.get("sub")
    username = claims.get("username")
    if not user_id_str or not username:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    try:
        user_id = int(user_id_str)
    except ValueError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    user = get_user_by_id(user_id)
    if not user or user["username"] != username:
        # Ensure claims and DB align; otherwise treat as invalid token
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    return {"user": user, "claims": claims}


# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------
@app.post("/register", status_code=201)
async def register(payload: RegisterRequest, response: Response):
    # Verify uniqueness of email and username
    try:
        # Check duplicates explicitly to provide a controlled 400 response
        conn = get_connection()
        with conn:
            cur = conn.execute(
                "SELECT 1 FROM users WHERE email = ? OR username = ?",
                (payload.email, payload.username),
            )
            if cur.fetchone():
                # Avoid exposing which field is duplicate to reduce enumeration vectors
                return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

            pwd_hash = hash_password(payload.password)
            conn.execute(
                """
                INSERT INTO users (email, username, password_hash, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (payload.email, payload.username, pwd_hash, datetime.now(timezone.utc).isoformat()),
            )
        return {"message": "Registration successful"}
    except sqlite3.Error:
        # Handle any DB constraint or unexpected error as Bad Request to match schema while avoiding details
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    except Exception as e:
        logger.exception("Error during registration: %s", e)
        # As per schema 400 exists; for unexpected we still keep 400 with generic message, avoiding internal details
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.post("/login")
async def login(payload: LoginRequest):
    try:
        user = get_user_by_email(payload.email)
        if not user:
            # Avoid user enumeration: generic message
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        if not verify_password(payload.password, user["password_hash"]):
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        token = create_jwt_token(user_id=user["id"], username=user["username"], email=user["email"])
        # Do not include sensitive info, only token and message as per schema
        return {"token": token, "message": "Login successful"}
    except Exception as e:
        logger.exception("Error during login: %s", e)
        # Do not leak details; keep generic unauthorized response
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})


@app.post("/set_secret")
async def set_secret(payload: SetSecretRequest, auth=Depends(require_auth)):
    try:
        auth_user = auth["user"]
        # Authorization check: ensure the username in body matches the authenticated user
        if auth_user["username"] != payload.username:
            # Treat mismatch as invalid token per schema message to avoid leaking existence of usernames
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
        upsert_secret(user_id=auth_user["id"], secret_text=payload.secret)
        return {"message": "Secret has been set successfully"}
    except HTTPException as e:
        # Pass through standard 401 from dependency or checks
        raise e
    except Exception as e:
        logger.exception("Error in set_secret: %s", e)
        # On unexpected errors, respond with 401 per schema for this route (avoid leaking server errors)
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})


@app.get("/get_secret")
async def get_secret(username: str, auth=Depends(require_auth)):
    try:
        auth_user = auth["user"]
        # Authorization check: only allow fetching own secret
        if auth_user["username"] != username:
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
        secret_text = get_secret_by_user_id(auth_user["id"])
        if secret_text is None:
            secret_text = ""
        return {"secret": secret_text}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.exception("Error in get_secret: %s", e)
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})


# ------------------------------------------------------------
# Main entrypoint
# ------------------------------------------------------------
if __name__ == "__main__":
    # Start the web server on 0.0.0.0:5000 as requested
    uvicorn.run("main:app", host="0.0.0.0", port=5000, log_level="info")