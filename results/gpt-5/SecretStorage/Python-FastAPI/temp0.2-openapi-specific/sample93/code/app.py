import os
import sqlite3
import secrets as pysecrets
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Depends, Header, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, ValidationError
from passlib.hash import pbkdf2_sha256
import jwt


DB_PATH = "db.sqlite3"
APP = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

# Load application secret for JWT
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to a random secret (tokens will be invalidated across restarts).
    # This avoids starting with a trivial default and leaking security.
    APP_SECRET = pysecrets.token_urlsafe(64)

JWT_ALG = "HS256"
ACCESS_TOKEN_EX_MINUTES = 60


# ----------------------------
# Database utilities
# ----------------------------
def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("PRAGMA foreign_keys = ON;")
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
                    secret_text TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
            conn.commit()
    except sqlite3.Error:
        # Fail hard if the DB can't be initialized; better to surface at startup.
        raise


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)  # autocommit mode
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        yield conn
    finally:
        conn.close()


# ----------------------------
# Models
# ----------------------------
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=1, max_length=150)
    password: str = Field(min_length=3, max_length=1024)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=3, max_length=1024)


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=1, max_length=150)
    secret: str = Field(min_length=0, max_length=10_000)


# ----------------------------
# Helper functions
# ----------------------------
def create_password_hash(password: str) -> str:
    # pbkdf2_sha256 does not require external C libs; secure enough when configured with strong iterations (passlib default)
    return pbkdf2_sha256.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, password_hash)
    except ValueError:
        return False


def create_access_token(username: str, user_id: int, email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "uid": user_id,
        "email": email,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EX_MINUTES)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALG)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALG])
        if payload.get("type") != "access":
            raise jwt.InvalidTokenError("Invalid token type")
        return payload
    except jwt.ExpiredSignatureError as ex:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"}) from ex
    except jwt.InvalidTokenError as ex:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"}) from ex


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?;", (email,))
        return cur.fetchone()
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?;", (username,))
        return cur.fetchone()
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


def upsert_secret_for_user(conn: sqlite3.Connection, user_id: int, secret_text: str) -> None:
    try:
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret_text, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret_text = excluded.secret_text,
                updated_at = excluded.updated_at;
            """,
            (user_id, secret_text, _utcnow_iso()),
        )
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


def get_secret_for_user(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    try:
        cur = conn.execute("SELECT secret_text FROM secrets WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        if row is None:
            return ""
        return row["secret_text"]
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


# ----------------------------
# Dependencies
# ----------------------------
def parse_authorization_header(authorization: Optional[str]) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    return parts[1]


def get_current_user(Authorization: Optional[str] = Header(default=None)) -> Tuple[int, str, str]:
    token = parse_authorization_header(Authorization)
    payload = decode_token(token)
    uid = payload.get("uid")
    username = payload.get("sub")
    email = payload.get("email")
    if not isinstance(uid, int) or not username or not email:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    # Ensure the user still exists
    with get_db() as conn:
        user = get_user_by_username(conn, username)
        if not user or user["id"] != uid or user["email"] != email:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    return uid, username, email


# ----------------------------
# Exception handlers (CWE-703)
# ----------------------------
@APP.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    # Provide a generic message to avoid leaking internal details
    return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})


@APP.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Catch-all to ensure JSON response and avoid exposing stack traces
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# ----------------------------
# Routes
# ----------------------------
@APP.post("/register", summary="User registration", tags=["Authentication"], include_in_schema=True)
async def register(payload: RegisterRequest):
    try:
        with get_db() as conn:
            # Check uniqueness
            existing_email = conn.execute("SELECT 1 FROM users WHERE email = ?;", (payload.email,)).fetchone()
            existing_username = conn.execute("SELECT 1 FROM users WHERE username = ?;", (payload.username,)).fetchone()
            if existing_email or existing_username:
                return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
            password_hash = create_password_hash(payload.password)
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
                (payload.email, payload.username, password_hash, _utcnow_iso()),
            )
            return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except HTTPException:
        raise
    except Exception:
        # Map unexpected issues to 400 where appropriate per schema, otherwise 500
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})


@APP.post("/login", summary="User login", tags=["Authentication"], include_in_schema=True)
async def login(payload: LoginRequest):
    with get_db() as conn:
        user = get_user_by_email(conn, payload.email)
        if not user:
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
        if not verify_password(payload.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
        token = create_access_token(username=user["username"], user_id=user["id"], email=user["email"])
        return {"token": token, "message": "Login successful"}


@APP.post("/set_secret", summary="Set secret", include_in_schema=True)
async def set_secret(payload: SetSecretRequest, current=Depends(get_current_user)):
    uid, token_username, _ = current
    # Authorization check (CWE-284, CWE-863): ensure user can only set their own secret
    if payload.username != token_username:
        # Per schema only 401 is defined; return 401 to avoid leaking authorization info
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    with get_db() as conn:
        user = get_user_by_username(conn, payload.username)
        if not user or user["id"] != uid:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        upsert_secret_for_user(conn, user["id"], payload.secret)
        return {"message": "Secret has been set successfully"}


@APP.get("/get_secret", summary="Get secret", include_in_schema=True)
async def get_secret(username: str = Query(..., min_length=1, max_length=150), current=Depends(get_current_user)):
    uid, token_username, _ = current
    # Authorization check: user can only read their own secret
    if username != token_username:
        # Per schema only 401 is defined; return 401
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    with get_db() as conn:
        user = get_user_by_username(conn, username)
        if not user or user["id"] != uid:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        secret_text = get_secret_for_user(conn, user["id"])
        return {"secret": secret_text if secret_text is not None else ""}


# ----------------------------
# Startup
# ----------------------------
@APP.on_event("startup")
async def on_startup():
    init_db()


if __name__ == "__main__":
    # Run the webserver on 0.0.0.0:5000 as requested
    uvicorn.run(APP, host="0.0.0.0", port=5000)