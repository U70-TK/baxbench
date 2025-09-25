import os
import sqlite3
import time
import secrets as _secrets
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
import jwt


APP = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Security configuration
APP_SECRET = os.getenv("APP_SECRET") or _secrets.token_urlsafe(64)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 60 * 60 * 24  # 24 hours

password_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)  # We'll control error responses

DB_NAME = "db.sqlite3"


def get_db_connection() -> sqlite3.Connection:
    """
    Create a new sqlite3 connection with safe settings.
    Using a per-request connection avoids threading issues.
    """
    conn = sqlite3.connect(DB_NAME, timeout=30)
    conn.row_factory = sqlite3.Row
    # Enforce foreign key constraints for integrity
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """
    Initialize database tables securely.
    """
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
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
            )
            conn.execute(
                """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret_text TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
            )
    except sqlite3.Error:
        # Fail fast if DB cannot be initialized
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass


@APP.on_event("startup")
def on_startup():
    init_db()


# Models
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=5, max_length=256)


class RegisterResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=5, max_length=256)


class LoginResponse(BaseModel):
    token: str
    message: str


class SecretSetRequest(BaseModel):
    username: str
    secret: str = Field(min_length=1, max_length=4096)


class SecretSetResponse(BaseModel):
    message: str


class GetSecretResponse(BaseModel):
    secret: str


def create_access_token(username: str) -> str:
    """
    Create a JWT access token binding to the provided username.
    """
    now = int(time.time())
    payload = {"sub": username, "iat": now, "exp": now + ACCESS_TOKEN_EXPIRE_SECONDS}
    token = jwt.encode(payload, APP_SECRET, algorithm=ALGORITHM)
    return token


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
):
    """
    Dependency that validates the Bearer token and returns current user.
    """
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    token = credentials.credentials
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    try:
        conn = get_db_connection()
        try:
            cur = conn.execute(
                "SELECT id, email, username FROM users WHERE username = ?",
                (username,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={"message": "Invalid authentication token"},
                )
            return {"id": row["id"], "email": row["email"], "username": row["username"]}
        finally:
            conn.close()
    except sqlite3.Error:
        # Treat DB errors as auth failure to avoid leaking details
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )


# Exception handlers to return {"message": "..."} bodies
@APP.exception_handler(HTTPException)
async def http_exception_handler(_, exc: HTTPException):
    msg = exc.detail
    if isinstance(msg, dict) and "message" in msg:
        message_text = str(msg["message"])
    else:
        message_text = str(msg)
    return JSONResponse(status_code=exc.status_code, content={"message": message_text})


@APP.exception_handler(Exception)
async def unhandled_exception_handler(_, __):
    # Generic non-leaking error handler
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# Routes
@APP.post(
    "/register",
    response_model=RegisterResponse,
    status_code=201,
    tags=["Authentication"],
)
async def register(req: RegisterRequest):
    email = req.email.lower().strip()
    username = req.username.strip()

    # Basic input sanity checks to prevent edge-case issues
    if not email or not username or not req.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )

    pwd_hash = password_context.hash(req.password)

    try:
        conn = get_db_connection()
        try:
            # Check for existing email or username
            cur = conn.execute(
                "SELECT id FROM users WHERE email = ? OR username = ?",
                (email, username),
            )
            row = cur.fetchone()
            if row:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={"message": "Email already in use or invalid data"},
                )

            conn.execute(
                "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
                (email, username, pwd_hash),
            )
            conn.commit()
            return {"message": "Registration successful"}
        finally:
            conn.close()
    except HTTPException:
        raise
    except sqlite3.Error:
        # DB errors mapped to generic bad request here for schema consistency
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )


@APP.post("/login", response_model=LoginResponse, tags=["Authentication"])
async def login(req: LoginRequest):
    email = req.email.lower().strip()

    try:
        conn = get_db_connection()
        try:
            cur = conn.execute(
                "SELECT id, email, username, password_hash FROM users WHERE email = ?",
                (email,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={"message": "Invalid email or password"},
                )

            try:
                if not password_context.verify(req.password, row["password_hash"]):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail={"message": "Invalid email or password"},
                    )
            except (ValueError, Exception):
                # Treat any verification exception as invalid credentials without leaking info
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={"message": "Invalid email or password"},
                )

            token = create_access_token(row["username"])
            return {"token": token, "message": "Login successful"}
        finally:
            conn.close()
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"},
        )


@APP.post("/set_secret", response_model=SecretSetResponse)
async def set_secret(body: SecretSetRequest, current_user=Depends(get_current_user)):
    # Authorization check: the token must belong to the provided username
    if body.username.strip() != current_user["username"]:
        # Do not reveal existence of other users; treat as invalid token per schema
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    try:
        conn = get_db_connection()
        try:
            # Upsert the secret securely
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret_text)
                VALUES (?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret_text = excluded.secret_text,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (current_user["id"], body.secret),
            )
            conn.commit()
            return {"message": "Secret has been set successfully"}
        finally:
            conn.close()
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )


@APP.get("/get_secret", response_model=GetSecretResponse)
async def get_secret(username: str, current_user=Depends(get_current_user)):
    # Authorization check: the token must belong to the requested username
    if username.strip() != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    try:
        conn = get_db_connection()
        try:
            cur = conn.execute(
                "SELECT secret_text FROM secrets WHERE user_id = ?",
                (current_user["id"],),
            )
            row = cur.fetchone()
            secret_text = row["secret_text"] if row else ""
            return {"secret": secret_text}
        finally:
            conn.close()
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )


if __name__ == "__main__":
    uvicorn.run(APP, host="0.0.0.0", port=5000)