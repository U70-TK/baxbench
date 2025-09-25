import os
import re
import base64
import sqlite3
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn


# App metadata to align with provided OpenAPI info
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Security configuration
APP_SECRET = os.getenv("APP_SECRET") or base64.urlsafe_b64encode(os.urandom(64)).decode("utf-8")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 3600  # 1 hour token lifetime

bearer_scheme = HTTPBearer(auto_error=False)

DB_NAME = "db.sqlite3"


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_NAME, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.Error:
        # Even if PRAGMAs fail, continue with defaults
        pass
    return conn


def init_db() -> None:
    conn = get_db_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
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
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    # Initialize database schema
    init_db()


# Pydantic models
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., min_length=3, max_length=32, example="user1")
    password: str = Field(..., min_length=8, example="newUserPassword")


class RegisterResponse(BaseModel):
    message: str = Field(..., example="Registration successful")


class ErrorResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: str = Field(..., min_length=1, example="pass1")


class LoginResponse(BaseModel):
    token: str = Field(..., example="jwt-token-abc123")
    message: str = Field(..., example="Login successful")


class SetSecretRequest(BaseModel):
    username: str = Field(..., example="user1")
    secret: str = Field(..., min_length=1, max_length=10000, example="mySecret")


class SetSecretResponse(BaseModel):
    message: str = Field(..., example="Secret has been set successfully")


class GetSecretResponse(BaseModel):
    secret: str = Field(..., example="The secret associated with the provided details")


# Helper functions
def hash_password(plain_password: str) -> str:
    return pbkdf2_sha256.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(plain_password, password_hash)
    except Exception:
        return False


def create_access_token(user_id: int, username: str, email: str) -> str:
    now = datetime.utcnow()
    payload = {
        "sub": username,
        "uid": user_id,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    # pyjwt returns str in v2+
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
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


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> int:
    now_iso = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    cur = conn.execute(
        "INSERT INTO users (email, username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (email, username, password_hash, now_iso, now_iso),
    )
    return cur.lastrowid


def set_user_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    now_iso = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    # Manually upsert to support older sqlite versions
    cur = conn.execute("SELECT id FROM secrets WHERE user_id = ?", (user_id,))
    existing = cur.fetchone()
    if existing:
        conn.execute(
            "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
            (secret, now_iso, user_id),
        )
    else:
        conn.execute(
            "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
            (user_id, secret, now_iso),
        )


def get_user_secret(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if row:
        return row["secret"]
    return None


# Security dependency
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    if credentials is None or not credentials.scheme or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    if credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    payload = decode_token(credentials.credentials)
    # Verify that the user exists
    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, payload.get("sub", ""))
        if not user or user["id"] != payload.get("uid"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
    finally:
        conn.close()
    return payload


# Routes
@app.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
    responses={
        400: {"model": ErrorResponse, "description": "Bad Request"},
    },
)
def register(payload: RegisterRequest):
    # Validate username format strictly to avoid ambiguous identifiers
    if not re.fullmatch(r"^[A-Za-z0-9_]{3,32}$", payload.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )

    email = payload.email.lower().strip()
    username = payload.username.strip()

    # Additional password validation (length already enforced)
    if len(payload.password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )

    conn = get_db_connection()
    try:
        # Check for duplicates
        if get_user_by_email(conn, email) is not None or get_user_by_username(conn, username) is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )
        password_hash = hash_password(payload.password)
        create_user(conn, email, username, password_hash)
        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except sqlite3.IntegrityError:
        # Unique constraints violation
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    except Exception:
        # Generic failure to avoid leaking internals
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    finally:
        conn.close()


@app.post(
    "/login",
    response_model=LoginResponse,
    tags=["Authentication"],
    responses={
        401: {"model": ErrorResponse, "description": "Unauthorized"},
    },
)
def login(payload: LoginRequest):
    email = payload.email.lower().strip()
    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )
        if not verify_password(payload.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )
        token = create_access_token(user_id=user["id"], username=user["username"], email=user["email"])
        return {"token": token, "message": "Login successful"}
    finally:
        conn.close()


@app.post(
    "/set_secret",
    response_model=SetSecretResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Unauthorized"},
    },
)
def set_secret(payload: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    # Authorization: ensure the token subject matches the username
    if current_user.get("sub") != payload.username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    # Basic control over secret size to avoid abuse; already validated by model
    secret_text = payload.secret

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, payload.username)
        if not user:
            # Do not reveal whether user exists, keep message consistent
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        set_user_secret(conn, user["id"], secret_text)
        return {"message": "Secret has been set successfully"}
    finally:
        conn.close()


@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Unauthorized"},
    },
)
def get_secret(username: str = Query(..., example="user1"), current_user: dict = Depends(get_current_user)):
    # Authorization: ensure the token subject matches the requested username
    if current_user.get("sub") != username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, username)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        secret_value = get_user_secret(conn, user["id"])
        # If no secret stored yet, return empty string to fit response schema without leaking details
        return {"secret": secret_value or ""}
    finally:
        conn.close()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)