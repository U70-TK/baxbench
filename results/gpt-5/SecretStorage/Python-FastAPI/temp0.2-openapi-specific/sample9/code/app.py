import os
import sqlite3
import time
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, Depends, Request, status, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field, validator
from passlib.hash import pbkdf2_sha256
import jwt

# ------------------------------------------------------------------------------
# Configuration and Security
# ------------------------------------------------------------------------------

APP = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

DB_PATH = "db.sqlite3"

JWT_ALG = "HS256"
JWT_EXPIRE_MINUTES = 60

APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET or len(APP_SECRET) < 32:
    # Generate a secure ephemeral secret if not provided or too short
    # Note: For production, always set a strong APP_SECRET via environment variable.
    APP_SECRET = secrets.token_urlsafe(64)

bearer_scheme = HTTPBearer(auto_error=False)

# ------------------------------------------------------------------------------
# Database Utilities
# ------------------------------------------------------------------------------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def get_db():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON;")
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ------------------------------------------------------------------------------
# Models
# ------------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., min_length=3, max_length=64, example="user1")
    password: str = Field(..., min_length=8, max_length=128, example="newUserPassword")

    @validator("username")
    def username_chars(cls, v: str) -> str:
        # allow alphanum, underscore, hyphen, dot
        if not all(c.isalnum() or c in ("_", "-", ".") for c in v):
            raise ValueError("Username may contain letters, numbers, '_', '-', '.' only")
        return v


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user@example.com")
    password: str = Field(..., min_length=1, example="mySecretPassword")


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, example="user1")
    secret: str = Field(..., min_length=0, max_length=10000, example="mySecret")


# ------------------------------------------------------------------------------
# Auth helpers
# ------------------------------------------------------------------------------

def create_access_token(user_id: int, username: str) -> str:
    now = datetime.now(tz=timezone.utc)
    exp = now + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALG)
    return token


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALG])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


async def auth_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: sqlite3.Connection = Depends(get_db),
):
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    payload = decode_token(token)
    if not payload:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    user_id = payload.get("sub")
    username = payload.get("username")
    if not user_id or not username:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        cur = db.execute("SELECT id, email, username FROM users WHERE id = ?;", (user_id,))
        row = cur.fetchone()
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not row or str(row["id"]) != str(user_id) or str(row["username"]).lower() != str(username).lower():
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    # return user context as dict
    return {"id": row["id"], "email": row["email"], "username": row["username"]}


# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@APP.post(
    "/register",
    summary="User registration",
    tags=["Authentication"],
)
def register(req: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    email = str(req.email).strip().lower()
    username = req.username.strip()
    password = req.password

    if len(password) < 8:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )

    # Create password hash with strong KDF
    try:
        password_hash = pbkdf2_sha256.hash(password)
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )

    try:
        # Check for duplicates first to give a cleaner error message
        cur = db.execute(
            "SELECT 1 FROM users WHERE email = ? OR username = ?;",
            (email, username),
        )
        if cur.fetchone():
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )

        db.execute(
            "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?);",
            (email, username, password_hash),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={"message": "Registration successful"},
    )


@APP.post(
    "/login",
    summary="User login",
    tags=["Authentication"],
)
def login(req: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    email = str(req.email).strip().lower()
    password = req.password

    try:
        cur = db.execute("SELECT id, username, password_hash FROM users WHERE email = ?;", (email,))
        row = cur.fetchone()
        if not row:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        password_hash = row["password_hash"]
        if not pbkdf2_sha256.verify(password, password_hash):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = create_access_token(user_id=row["id"], username=row["username"])
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"token": token, "message": "Login successful"},
        )
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid email or password"},
            headers={"WWW-Authenticate": "Bearer"},
        )


@APP.post(
    "/set_secret",
    summary="Set secret",
)
def set_secret(
    req: SetSecretRequest,
    user_ctx=Depends(auth_user),
    db: sqlite3.Connection = Depends(get_db),
):
    # If auth_user returned a JSONResponse (error), return it directly
    if isinstance(user_ctx, JSONResponse):
        return user_ctx

    # Authorization: ensure the token subject matches the provided username
    if str(user_ctx["username"]).lower() != req.username.strip().lower():
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Fetch the user id again to be sure (case-insensitive username lookup)
    try:
        cur = db.execute(
            "SELECT id FROM users WHERE username = ? COLLATE NOCASE;",
            (req.username.strip(),),
        )
        row = cur.fetchone()
        if not row or int(row["id"]) != int(user_ctx["id"]):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid authentication token"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        user_id = row["id"]
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Store/Update secret securely (parameterized queries)
    try:
        db.execute(
            """
            INSERT INTO secrets (user_id, secret, created_at, updated_at)
            VALUES (?, ?, datetime('now'), datetime('now'))
            ON CONFLICT(user_id) DO UPDATE SET
                secret=excluded.secret,
                updated_at=datetime('now');
            """,
            (user_id, req.secret),
        )
        db.commit()
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "An unexpected error occurred"},
        )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": "Secret has been set successfully"},
    )


@APP.get(
    "/get_secret",
    summary="Get secret",
)
def get_secret(
    username: str = Query(..., example="user1", min_length=3, max_length=64),
    user_ctx=Depends(auth_user),
    db: sqlite3.Connection = Depends(get_db),
):
    # If auth_user returned a JSONResponse (error), return it directly
    if isinstance(user_ctx, JSONResponse):
        return user_ctx

    # Authorization: ensure the token subject matches the requested username
    if str(user_ctx["username"]).lower() != username.strip().lower():
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        cur = db.execute(
            "SELECT s.secret FROM secrets s JOIN users u ON u.id = s.user_id WHERE u.username = ? COLLATE NOCASE;",
            (username.strip(),),
        )
        row = cur.fetchone()
        secret_value = row["secret"] if row else ""
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"secret": secret_value},
        )
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "An unexpected error occurred"},
        )


# ------------------------------------------------------------------------------
# Startup initialization
# ------------------------------------------------------------------------------

@APP.on_event("startup")
def on_startup():
    try:
        init_db()
    except Exception:
        # Fail-safe: try to recreate DB on fatal init error
        try:
            if os.path.exists(DB_PATH):
                os.remove(DB_PATH)
            init_db()
        except Exception:
            # If even recovery fails, we let FastAPI show a generic error later
            pass


# ------------------------------------------------------------------------------
# Entrypoint
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(APP, host="0.0.0.0", port=5000)