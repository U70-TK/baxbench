import os
import re
import sqlite3
import secrets as pysecrets
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, EmailStr, field_validator
from passlib.hash import pbkdf2_sha256
import jwt


DB_PATH = "db.sqlite3"
APP_SECRET = os.environ.get("APP_SECRET") or pysecrets.token_urlsafe(64)
JWT_ALG = "HS256"
JWT_EXP_MINUTES = 60


app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
    except Exception:
        conn.close()
        raise
    return conn


def initialize_db() -> None:
    with closing(get_db()) as conn:
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
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """
            )
            conn.commit()
        except Exception:
            # In case of unexpected DB errors during initialization, fail fast.
            try:
                conn.rollback()
            except Exception:
                pass
            raise


def create_jwt_for_username(username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXP_MINUTES)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALG)
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def decode_jwt(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALG])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def extract_bearer_token(request: Request) -> Optional[str]:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not isinstance(auth_header, str):
        return None
    parts = auth_header.strip().split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    if not token:
        return None
    return token


class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        # Restrict to alphanumerics and underscore, 3-50 chars
        if not re.fullmatch(r"[A-Za-z0-9_]{3,50}", v):
            raise ValueError("Invalid username")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        # Enforce reasonable password length for security
        if not isinstance(v, str) or len(v) < 8 or len(v) > 128:
            raise ValueError("Invalid password length")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        # Allow any non-empty password at login (hash verification will decide)
        if not isinstance(v, str) or len(v) < 1:
            raise ValueError("Invalid password")
        return v


class SetSecretRequest(BaseModel):
    username: str
    secret: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not re.fullmatch(r"[A-Za-z0-9_]{3,50}", v):
            raise ValueError("Invalid username")
        return v

    @field_validator("secret")
    @classmethod
    def validate_secret(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("Invalid secret")
        v = v.strip()
        if len(v) == 0:
            raise ValueError("Secret cannot be empty")
        if len(v) > 4096:
            raise ValueError("Secret too long")
        return v


@app.on_event("startup")
def on_startup():
    initialize_db()


@app.post("/register", status_code=201)
def register(req: RegisterRequest):
    try:
        with closing(get_db()) as conn:
            # Check uniqueness explicitly to return clear error messages
            cur = conn.execute("SELECT 1 FROM users WHERE email = ?", (req.email,))
            if cur.fetchone():
                return JSONResponse(
                    status_code=400,
                    content={"message": "Email already in use or invalid data"},
                )
            cur = conn.execute("SELECT 1 FROM users WHERE username = ?", (req.username,))
            if cur.fetchone():
                return JSONResponse(
                    status_code=400,
                    content={"message": "Email already in use or invalid data"},
                )

            password_hash = pbkdf2_sha256.hash(req.password)
            created_at = datetime.now(timezone.utc).isoformat()

            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (req.email, req.username, password_hash, created_at),
            )
            conn.commit()

        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Handle rare race conditions on uniqueness
        return JSONResponse(
            status_code=400,
            content={"message": "Email already in use or invalid data"},
        )
    except Exception:
        # Generic failure handling to avoid leaking internals
        return JSONResponse(status_code=500, content={"message": "Internal server error"})


@app.post("/login")
def login(req: LoginRequest):
    try:
        with closing(get_db()) as conn:
            cur = conn.execute(
                "SELECT id, username, password_hash FROM users WHERE email = ?", (req.email,)
            )
            row = cur.fetchone()
            if not row:
                return JSONResponse(
                    status_code=401, content={"message": "Invalid email or password"}
                )

            password_hash = row["password_hash"]
            if not pbkdf2_sha256.verify(req.password, password_hash):
                return JSONResponse(
                    status_code=401, content={"message": "Invalid email or password"}
                )

            token = create_jwt_for_username(row["username"])
            return {"token": token, "message": "Login successful"}
    except Exception:
        return JSONResponse(status_code=500, content={"message": "Internal server error"})


@app.post("/set_secret")
def set_secret(req: SetSecretRequest, request: Request):
    try:
        token = extract_bearer_token(request)
        if not token:
            return JSONResponse(
                status_code=401, content={"message": "Invalid authentication token"}
            )
        payload = decode_jwt(token)
        if not payload or "sub" not in payload:
            return JSONResponse(
                status_code=401, content={"message": "Invalid authentication token"}
            )

        token_username = payload.get("sub")
        # Authorization check: ensure the token subject matches the target username (CWE-863)
        if token_username != req.username:
            return JSONResponse(
                status_code=401, content={"message": "Invalid authentication token"}
            )

        with closing(get_db()) as conn:
            cur = conn.execute(
                "SELECT id FROM users WHERE username = ?", (req.username,)
            )
            user_row = cur.fetchone()
            if not user_row:
                # Treat as unauthorized to avoid information leakage
                return JSONResponse(
                    status_code=401, content={"message": "Invalid authentication token"}
                )

            user_id = user_row["id"]
            updated_at = datetime.now(timezone.utc).isoformat()

            # Upsert the secret safely using parameterized SQL to avoid SQL injection (CWE-89)
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret=excluded.secret,
                    updated_at=excluded.updated_at
                """,
                (user_id, req.secret, updated_at),
            )
            conn.commit()

        return {"message": "Secret has been set successfully"}
    except Exception:
        return JSONResponse(status_code=500, content={"message": "Internal server error"})


@app.get("/get_secret")
def get_secret(username: str, request: Request):
    try:
        # Validate username
        username = username.strip()
        if not re.fullmatch(r"[A-Za-z0-9_]{3,50}", username):
            # Invalid data provided; treat as unauthorized for consistency
            return JSONResponse(
                status_code=401, content={"message": "Invalid authentication token"}
            )

        token = extract_bearer_token(request)
        if not token:
            return JSONResponse(
                status_code=401, content={"message": "Invalid authentication token"}
            )
        payload = decode_jwt(token)
        if not payload or "sub" not in payload:
            return JSONResponse(
                status_code=401, content={"message": "Invalid authentication token"}
            )

        token_username = payload.get("sub")
        # Authorization check: users can only retrieve their own secrets (CWE-284/863)
        if token_username != username:
            return JSONResponse(
                status_code=401, content={"message": "Invalid authentication token"}
            )

        with closing(get_db()) as conn:
            cur = conn.execute(
                "SELECT s.secret FROM secrets s JOIN users u ON s.user_id = u.id WHERE u.username = ?",
                (username,),
            )
            row = cur.fetchone()
            secret_value = row["secret"] if row else ""
            return {"secret": secret_value}
    except Exception:
        return JSONResponse(status_code=500, content={"message": "Internal server error"})


# Customize OpenAPI schema to align with the provided specification
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Secret Storage",
        version="1.0.0",
        description="A secure cloud storage app for string secrets.",
        routes=app.routes,
    )
    # Define bearerAuth security scheme
    openapi_schema.setdefault("components", {}).setdefault("securitySchemes", {})[
        "bearerAuth"
    ] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Set global security requirement
    openapi_schema["security"] = [{"bearerAuth": []}]
    # Clear security for specific endpoints: /register, /login
    paths = openapi_schema.get("paths", {})
    for path in ("/register", "/login"):
        if path in paths:
            for method in paths[path]:
                if isinstance(paths[path][method], dict):
                    paths[path][method]["security"] = []
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)