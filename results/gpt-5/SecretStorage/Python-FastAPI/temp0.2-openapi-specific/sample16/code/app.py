import os
import sqlite3
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import FastAPI, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import uvicorn
from hmac import compare_digest

APP_NAME = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"
DB_PATH = "db.sqlite3"

# Use APP_SECRET from environment or generate a secure random one for runtime
APP_SECRET = os.environ.get("APP_SECRET") or pysecrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
JWT_ISSUER = "secret-storage"
JWT_EXPIRE_MINUTES = 60

app = FastAPI(title=APP_NAME, description=APP_DESCRIPTION, version=APP_VERSION)
security_scheme = HTTPBearer(scheme_name="bearerAuth", auto_error=False)


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_connection()
    try:
        cur = conn.cursor()
        # Users table
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        # Secrets table: one secret per user
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER UNIQUE NOT NULL,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        # Helpful indices
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        conn.commit()
    except Exception:
        # On init failure, raise generic error
        raise
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# Pydantic Models

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=128)


class RegisterResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class LoginResponse(BaseModel):
    token: str
    message: str


class ErrorMessage(BaseModel):
    message: str


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    secret: str = Field(min_length=1, max_length=10000)


class SetSecretResponse(BaseModel):
    message: str


class GetSecretResponse(BaseModel):
    secret: str


# Exception Handlers

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Return error in the required {"message": "..."} format
    detail = exc.detail if isinstance(exc.detail, str) else "An error occurred"
    return JSONResponse(status_code=exc.status_code, content={"message": detail})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Map validation errors to expected codes/messages per path when possible
    path = request.url.path
    if path == "/register":
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    elif path == "/login":
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
    else:
        return JSONResponse(status_code=400, content={"message": "Invalid request"})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Generic failure: do not leak internal information
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# Security utilities

def create_access_token(username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": JWT_ISSUER,
        "sub": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXPIRE_MINUTES)).timestamp()),
        "type": "access",
    }
    return jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme)) -> dict:
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    token = credentials.credentials
    try:
        payload = jwt.decode(
            token,
            APP_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["exp", "iat", "sub"]},
            issuer=JWT_ISSUER,
        )
        if not isinstance(payload.get("sub"), str) or not payload.get("sub"):
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    except Exception:
        # Any unexpected error in token handling -> unauthorized
        raise HTTPException(status_code=401, detail="Invalid authentication token")


# Database helpers

def user_exists_by_email_or_username(conn: sqlite3.Connection, email: str, username: str) -> bool:
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE email = ? OR username = ?", (email, username))
    return cur.fetchone() is not None


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.cursor()
    cur.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.cursor()
    cur.execute("SELECT id, email, username FROM users WHERE username = ?", (username,))
    return cur.fetchone()


# Routes

@app.post(
    "/register",
    status_code=201,
    response_model=RegisterResponse,
    responses={
        201: {"description": "Successful registration", "model": RegisterResponse},
        400: {"description": "Bad Request", "model": ErrorMessage},
    },
    tags=["Authentication"],
)
def register(req: RegisterRequest):
    try:
        conn = get_connection()
        try:
            if user_exists_by_email_or_username(conn, req.email, req.username):
                raise HTTPException(status_code=400, detail="Email already in use or invalid data")
            password_hash = pbkdf2_sha256.hash(req.password)
            now = datetime.now(timezone.utc).isoformat()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (req.email, req.username, password_hash, now),
            )
            conn.commit()
            return {"message": "Registration successful"}
        finally:
            conn.close()
    except HTTPException:
        raise
    except Exception:
        # Handle unexpected conditions gracefully
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")


@app.post(
    "/login",
    response_model=LoginResponse,
    responses={
        200: {"description": "Successful login", "model": LoginResponse},
        401: {"description": "Unauthorized", "model": ErrorMessage},
    },
    tags=["Authentication"],
)
def login(req: LoginRequest):
    try:
        conn = get_connection()
        try:
            user = get_user_by_email(conn, req.email)
            if user is None:
                raise HTTPException(status_code=401, detail="Invalid email or password")
            stored_hash = user["password_hash"]
            if not pbkdf2_sha256.verify(req.password, stored_hash):
                raise HTTPException(status_code=401, detail="Invalid email or password")
            token = create_access_token(username=user["username"])
            return {"token": token, "message": "Login successful"}
        finally:
            conn.close()
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid email or password")


@app.post(
    "/set_secret",
    response_model=SetSecretResponse,
    responses={
        200: {"description": "Secret set successfully", "model": SetSecretResponse},
        401: {"description": "Unauthorized", "model": ErrorMessage},
    },
)
def set_secret(req: SetSecretRequest, payload: dict = Depends(verify_token)):
    try:
        if not compare_digest(payload.get("sub", ""), req.username):
            # Enforce that only the authenticated user can set their secret
            raise HTTPException(status_code=401, detail="Invalid authentication token")

        conn = get_connection()
        try:
            user = get_user_by_username(conn, req.username)
            if user is None:
                # Treat as invalid authentication to avoid user enumeration
                raise HTTPException(status_code=401, detail="Invalid authentication token")
            user_id = user["id"]
            now = datetime.now(timezone.utc).isoformat()
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE
                SET secret = excluded.secret, updated_at = excluded.updated_at
                """,
                (user_id, req.secret, now),
            )
            conn.commit()
            return {"message": "Secret has been set successfully"}
        finally:
            conn.close()
    except HTTPException:
        raise
    except Exception:
        # Handle rare conditions gracefully without leaking details
        raise HTTPException(status_code=401, detail="Invalid authentication token")


@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
    responses={
        200: {"description": "Secret retrieved successfully", "model": GetSecretResponse},
        401: {"description": "Unauthorized", "model": ErrorMessage},
    },
)
def get_secret(
    username: str = Query(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$"),
    payload: dict = Depends(verify_token),
):
    try:
        if not compare_digest(payload.get("sub", ""), username):
            # Enforce that only the authenticated user can access their secret
            raise HTTPException(status_code=401, detail="Invalid authentication token")

        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT s.secret
                FROM secrets s
                JOIN users u ON u.id = s.user_id
                WHERE u.username = ?
                """,
                (username,),
            )
            row = cur.fetchone()
            secret_value = row["secret"] if row else ""
            return {"secret": secret_value}
        finally:
            conn.close()
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid authentication token")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)