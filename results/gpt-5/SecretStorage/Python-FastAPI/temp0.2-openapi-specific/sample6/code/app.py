import os
import re
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field, field_validator
from passlib.hash import pbkdf2_sha256
import jwt


DB_PATH = "db.sqlite3"
ALGORITHM = "HS256"
DEFAULT_TOKEN_TTL_SECONDS = 3600  # 1 hour


def get_app_secret() -> str:
    secret = os.getenv("APP_SECRET")
    if not secret:
        # Generate a random secret if not provided; log a warning to stderr.
        # In production, always set APP_SECRET via environment.
        secret = os.urandom(32).hex()
        print(
            "WARNING: APP_SECRET was not set. Generated a temporary secret for this process. "
            "Set APP_SECRET in the environment for consistent JWT signing.",
            file=sys.stderr,
        )
    return secret


APP_SECRET = get_app_secret()


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    # Enable foreign keys and set WAL for better concurrency
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


def init_db() -> None:
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    user_id INTEGER PRIMARY KEY,
                    secret TEXT NOT NULL,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
    finally:
        conn.close()


app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

security = HTTPBearer(auto_error=False)


# ---- Pydantic Models ----
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=4, max_length=128)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_]+", v):
            raise ValueError("username must contain only letters, digits, and underscore")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=128)


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    secret: str = Field(..., min_length=1, max_length=4096)


# ---- Helper Responses ----
def json_message(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"message": message})


def unauthorized_token_response() -> JSONResponse:
    return json_message(401, "Invalid authentication token")


# ---- Authentication Dependency ----
async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
):
    if credentials is None or not credentials.scheme.lower() == "bearer":
        # No/invalid auth header
        raise_auth = unauthorized_token_response()
        raise_auth.headers = {"WWW-Authenticate": "Bearer"}
        # FastAPI expects exceptions; but we return a Response directly in endpoints instead.
        # Here we raise an exception in a way endpoints can catch? We'll return a sentinel.
        # To conform simply raise an Exception and handle in endpoint—but complexity adds.
        # Instead, we will return a dict with error to let endpoints reply consistently.
        return {"_auth_error": True}

    token = credentials.credentials
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        username = payload.get("sub")
        uid = payload.get("uid")
        if not username or not uid:
            return {"_auth_error": True}
        # Verify that user still exists
        conn = get_db_connection()
        try:
            cur = conn.execute(
                "SELECT id, email, username FROM users WHERE id = ? LIMIT 1", (uid,)
            )
            row = cur.fetchone()
            if not row or row["username"] != username:
                return {"_auth_error": True}
            return {"id": row["id"], "username": row["username"]}
        finally:
            conn.close()
    except jwt.ExpiredSignatureError:
        return {"_auth_error": True}
    except jwt.InvalidTokenError:
        return {"_auth_error": True}


# ---- Utility Functions ----
def create_jwt_token(user_id: int, username: str, ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "uid": user_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=ALGORITHM)
    return token


# ---- Routes ----
@app.post("/register")
async def register(data: RegisterRequest):
    # Note: 201 on success, 400 on invalid/duplicate
    conn = get_db_connection()
    try:
        with conn:
            try:
                hashed = pbkdf2_sha256.hash(data.password)
            except Exception:
                return json_message(400, "Email already in use or invalid data")

            try:
                conn.execute(
                    "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
                    (data.email, data.username, hashed),
                )
            except sqlite3.IntegrityError:
                # Duplicate email or username
                return json_message(400, "Email already in use or invalid data")

        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except Exception:
        # Unexpected error
        return json_message(400, "Email already in use or invalid data")
    finally:
        conn.close()


@app.post("/login")
async def login(data: LoginRequest):
    # 200 with {token, message} on success
    # 401 with {message} on failure
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ? LIMIT 1", (data.email,))
        row = cur.fetchone()
        if not row:
            return json_message(401, "Invalid email or password")
        try:
            if not pbkdf2_sha256.verify(data.password, row["password_hash"]):
                return json_message(401, "Invalid email or password")
        except Exception:
            # Verification failure
            return json_message(401, "Invalid email or password")

        token = create_jwt_token(row["id"], row["username"])
        return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})
    except Exception:
        return json_message(401, "Invalid email or password")
    finally:
        conn.close()


@app.post("/set_secret")
async def set_secret(req: Request, data: SetSecretRequest, current=Depends(get_current_user)):
    # Requires valid bearer token; username in body must match token subject
    if not isinstance(current, dict) or current.get("_auth_error"):
        return unauthorized_token_response()

    token_username = current.get("username")
    if token_username != data.username:
        # Prevent setting secrets for other users (CWE-863/CWE-284)
        return unauthorized_token_response()

    conn = get_db_connection()
    try:
        with conn:
            # Upsert secret for user_id
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret = excluded.secret,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (current["id"], data.secret),
            )
        return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})
    except Exception:
        return unauthorized_token_response()
    finally:
        conn.close()


@app.get("/get_secret")
async def get_secret(username: str, current=Depends(get_current_user)):
    # Requires valid bearer token; username in query must match token subject
    if not isinstance(current, dict) or current.get("_auth_error"):
        return unauthorized_token_response()

    if current.get("username") != username:
        # Prevent reading secrets for other users (CWE-863/CWE-284)
        return unauthorized_token_response()

    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ? LIMIT 1", (current["id"],))
        row = cur.fetchone()
        secret_value = row["secret"] if row else ""
        return JSONResponse(status_code=200, content={"secret": secret_value})
    except Exception:
        return unauthorized_token_response()
    finally:
        conn.close()


# ---- Startup ----
@app.on_event("startup")
def on_startup():
    init_db()


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=5000)