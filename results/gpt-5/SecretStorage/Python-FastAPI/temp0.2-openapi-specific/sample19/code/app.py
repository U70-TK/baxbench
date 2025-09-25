import os
import re
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.exceptions import RequestValidationError
from starlette.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr
from passlib.context import CryptContext
import jwt


# Constants and configuration
DB_PATH = "db.sqlite3"
JWT_ALGORITHM = "HS256"
APP_SECRET = os.environ.get("APP_SECRET", None)
if not APP_SECRET or len(APP_SECRET) < 16:
    # Fallback to a random secret if not provided; this will invalidate tokens across restarts.
    # In production, always provide a strong APP_SECRET via environment variables.
    import secrets

    APP_SECRET = secrets.token_urlsafe(64)

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)


# Utility functions
def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
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
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER PRIMARY KEY,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        return False


def normalize_email(email: str) -> str:
    return email.strip().lower()


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,50}$")


def validate_username(username: str) -> bool:
    return bool(USERNAME_PATTERN.match(username.strip()))


def create_access_token(username: str, email: str, expires_delta: Optional[timedelta] = None) -> str:
    now = int(time.time())
    exp = now + int(expires_delta.total_seconds()) if expires_delta else now + 24 * 3600
    payload = {
        "sub": username,
        "email": email,
        "iat": now,
        "exp": exp,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?", (email,))
    return cur.fetchone()


# Pydantic models
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6, max_length=256)


class RegisterResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=256)


class LoginResponse(BaseModel):
    token: str
    message: str


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    secret: str = Field(..., min_length=1)


class SetSecretResponse(BaseModel):
    message: str


class GetSecretResponse(BaseModel):
    secret: str


# FastAPI app
app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")


# Exception handlers to return consistent {"message": "..."} responses
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    message = exc.detail if isinstance(exc.detail, str) else "An error occurred"
    return JSONResponse(status_code=exc.status_code, content={"message": message})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError):
    # Return 400 for invalid inputs to match the schema's "Bad Request" for registration
    return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})


# Auth dependency
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    if credentials is None or not credentials.scheme.lower() == "bearer" or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    token = credentials.credentials
    payload = decode_token(token)
    username = payload.get("sub")
    if not username or not isinstance(username, str):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        user_row = get_user_by_username(conn, username)
        if not user_row:
            # Token refers to a non-existent user
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        return {"id": user_row["id"], "email": user_row["email"], "username": user_row["username"]}
    finally:
        conn.close()


# Routes
@app.post("/register", response_model=RegisterResponse, status_code=201)
async def register(data: RegisterRequest):
    email = normalize_email(data.email)
    username = data.username.strip()

    if not validate_username(username):
        # Invalid username format
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

    password_hash = hash_password(data.password)
    now = datetime.utcnow().isoformat() + "Z"

    conn = get_db_connection()
    try:
        # Check duplicates
        existing_email = get_user_by_email(conn, email)
        if existing_email:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
        existing_username = get_user_by_username(conn, username)
        if existing_username:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, now),
        )
        conn.commit()
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Any uniqueness or constraint violation
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    except sqlite3.Error:
        # Unexpected database error - do not leak details
        return JSONResponse(status_code=500, content={"message": "Internal server error"})
    finally:
        conn.close()


@app.post("/login", response_model=LoginResponse)
async def login(data: LoginRequest):
    email = normalize_email(data.email)
    conn = get_db_connection()
    try:
        user_row = get_user_by_email(conn, email)
        if not user_row or not verify_password(data.password, user_row["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        token = create_access_token(username=user_row["username"], email=user_row["email"], expires_delta=timedelta(hours=24))
        return {"token": token, "message": "Login successful"}
    except sqlite3.Error:
        return JSONResponse(status_code=500, content={"message": "Internal server error"})
    finally:
        conn.close()


@app.post("/set_secret", response_model=SetSecretResponse)
async def set_secret(data: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    # Authorization: ensure the username in the request matches the token subject
    if data.username.strip() != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        now = datetime.utcnow().isoformat() + "Z"
        # Upsert secret: secrets.user_id is PRIMARY KEY, so ON CONFLICT do update
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=excluded.updated_at
            """,
            (current_user["id"], data.secret, now),
        )
        conn.commit()
        return {"message": "Secret has been set successfully"}
    except sqlite3.Error:
        return JSONResponse(status_code=500, content={"message": "Internal server error"})
    finally:
        conn.close()


@app.get("/get_secret", response_model=GetSecretResponse)
async def get_secret(username: str, current_user: dict = Depends(get_current_user)):
    # Authorization: ensure the username in the request matches the token subject
    if username.strip() != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        cur = conn.execute(
            "SELECT secret FROM secrets WHERE user_id = ?",
            (current_user["id"],),
        )
        row = cur.fetchone()
        secret_value = row["secret"] if row and row["secret"] is not None else ""
        return {"secret": secret_value}
    except sqlite3.Error:
        return JSONResponse(status_code=500, content={"message": "Internal server error"})
    finally:
        conn.close()


# Startup event to initialize the database
@app.on_event("startup")
async def on_startup():
    init_db()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=5000, reload=False)