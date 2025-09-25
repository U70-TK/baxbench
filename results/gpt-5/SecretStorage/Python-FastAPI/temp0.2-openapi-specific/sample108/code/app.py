import os
import re
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, EmailStr, Field, constr
from passlib.hash import pbkdf2_sha256
import jwt

# Application setup
app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secret-storage")

# Constants and configurations
DB_PATH = "db.sqlite3"
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,32}$")
MAX_SECRET_LENGTH = 8192  # Limit to mitigate abuse
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Load application secret for JWT
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Generate a per-process fallback secret if not provided. For production, set APP_SECRET.
    import secrets as _secrets  # stdlib secrets
    APP_SECRET = _secrets.token_urlsafe(64)
    logger.warning("APP_SECRET not set. Using a temporary in-memory secret. Set APP_SECRET for production.")

JWT_ALGORITHM = "HS256"
JWT_ISSUER = "secret-storage-app"

# Precompute a fake hash for constant-time password verification fallback
_FAKE_PW_HASH = pbkdf2_sha256.hash("not_the_password")


# Pydantic models
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: constr(min_length=3, max_length=32) = Field(..., example="user1")
    password: constr(min_length=8, max_length=1024) = Field(..., example="newUserPassword")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user@example.com")
    password: constr(min_length=1, max_length=1024) = Field(..., example="mySecretPassword")


class SetSecretRequest(BaseModel):
    username: constr(min_length=3, max_length=32) = Field(..., example="user1")
    secret: constr(min_length=1, max_length=MAX_SECRET_LENGTH) = Field(..., example="mySecret")


# Database helpers
def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at DATETIME NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER PRIMARY KEY,
                secret TEXT NOT NULL,
                updated_at DATETIME NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    except sqlite3.Error as e:
        logger.error("Failed to initialize database: %s", str(e))
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass


def get_db():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.on_event("startup")
def on_startup():
    init_db()


# Security helpers
def create_access_token(username: str, email: str) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "email": email,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "iss": JWT_ISSUER,
        "type": "access",
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM], issuer=JWT_ISSUER, options={"require": ["exp", "iat", "nbf", "iss"]})
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    return payload


def get_bearer_token_from_header(request: Request) -> str:
    auth = request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    token = auth[7:].strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    return token


def get_current_user(request: Request, db: sqlite3.Connection = Depends(get_db)) -> dict:
    token = get_bearer_token_from_header(request)
    payload = decode_access_token(token)
    username = payload.get("sub")
    email = payload.get("email")
    if not username or not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    try:
        cur = db.execute("SELECT id, email, username FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if not row or row["email"].lower() != email.lower():
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        return {"id": row["id"], "username": row["username"], "email": row["email"]}
    except sqlite3.Error:
        # Treat DB errors during auth as unauthorized to avoid leaking info
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


# Validators
def validate_username(username: str):
    if not USERNAME_PATTERN.match(username):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid username format")


# Exception handlers to avoid leaking internals (CWE-703)
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"message": "Invalid request data"})


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Normalize to the expected response shape with "message"
    detail = exc.detail if isinstance(exc.detail, str) else "An error occurred"
    return JSONResponse(status_code=exc.status_code, content={"message": detail})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception: %s", str(exc))
    return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"message": "Internal server error"})


# Routes
@app.post("/register", status_code=201, tags=["Authentication"])
def register(body: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    email = body.email.strip().lower()
    username = body.username.strip()
    password = body.password

    validate_username(username)

    # Additional weak password checks (basic)
    if len(password) < 8:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")

    try:
        # Check uniqueness
        cur = db.execute("SELECT 1 FROM users WHERE email = ? OR username = ?", (email, username))
        if cur.fetchone():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")

        password_hash = pbkdf2_sha256.hash(password)
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, now),
        )
        db.commit()
        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except sqlite3.IntegrityError:
        # Unique constraint violation
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")
    except sqlite3.Error:
        # Generic DB error
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


@app.post("/login", tags=["Authentication"])
def login(body: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    email = body.email.strip().lower()
    password = body.password

    try:
        cur = db.execute("SELECT id, username, password_hash, email FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        if not row:
            # Constant-time mitigation to avoid user enumeration
            try:
                pbkdf2_sha256.verify(password, _FAKE_PW_HASH)
            except Exception:
                pass
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        stored_hash = row["password_hash"]
        if not pbkdf2_sha256.verify(password, stored_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        token = create_access_token(username=row["username"], email=row["email"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


@app.post("/set_secret")
def set_secret(body: SetSecretRequest, current_user: dict = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    username = body.username.strip()
    secret = body.secret

    validate_username(username)

    # Authorization check: users can only set their own secret (CWE-284/CWE-863)
    if username != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    try:
        # Ensure user exists and get id
        cur = db.execute("SELECT id FROM users WHERE username = ?", (username,))
        user_row = cur.fetchone()
        if not user_row:
            # Should not happen for authenticated user; treat as unauthorized to avoid leaking
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        user_id = user_row["id"]

        now = datetime.now(timezone.utc).isoformat()
        # Upsert secret securely using parameterized SQL (CWE-89)
        db.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret = excluded.secret,
                updated_at = excluded.updated_at
            """,
            (user_id, secret, now),
        )
        db.commit()
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


@app.get("/get_secret")
def get_secret(username: str, current_user: dict = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    username = username.strip()
    validate_username(username)

    # Authorization: users can only retrieve their own secret
    if username != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    try:
        cur = db.execute("SELECT id FROM users WHERE username = ?", (username,))
        user_row = cur.fetchone()
        if not user_row:
            # Avoid leaking whether the user exists
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        user_id = user_row["id"]

        cur2 = db.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        sec_row = cur2.fetchone()
        secret_value = sec_row["secret"] if sec_row else ""
        return {"secret": secret_value}
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)