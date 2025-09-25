import os
import sqlite3
import datetime
import secrets as pysecrets
import re
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Depends, status, Query
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn


# Application initialization with metadata matching the provided OpenAPI schema
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

DB_PATH = "db.sqlite3"


def get_app_secret() -> str:
    # Use APP_SECRET from environment; fallback to a random secure token if not provided
    # Note: For production, you should set APP_SECRET to a stable, strong secret.
    secret = os.environ.get("APP_SECRET")
    if not secret:
        # Generate an ephemeral secret; warns in logs
        secret = pysecrets.token_urlsafe(64)
    return secret


JWT_SECRET = get_app_secret()
JWT_ALGORITHM = "HS256"
JWT_EXP_SECONDS = 3600  # 1 hour token validity


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    # Apply secure PRAGMAs
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
    except sqlite3.Error:
        # If PRAGMA fails, continue; not critical
        pass
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
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
    except sqlite3.Error as e:
        # If DB initialization fails, raise an HTTPException that will be handled
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# Pydantic models for request bodies and responses
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_]+$")
    password: str = Field(..., min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_]+$")
    secret: str = Field(..., min_length=1, max_length=8192)


def create_jwt_token(user_id: int, username: str, email: str) -> str:
    now = datetime.datetime.utcnow()
    payload = {
        "sub": username,
        "uid": user_id,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(seconds=JWT_EXP_SECONDS)).timestamp()),
        "jti": pysecrets.token_urlsafe(16),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    # pyjwt returns str in v2.x
    return token


def decode_jwt_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")


def extract_bearer_token(request: Request) -> str:
    auth = request.headers.get("Authorization")
    if not auth:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    parts = auth.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    return parts[1]


def get_current_user(request: Request) -> sqlite3.Row:
    token = extract_bearer_token(request)
    payload = decode_jwt_token(token)
    username = payload.get("sub")
    uid = payload.get("uid")
    if not username or not uid:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    conn = get_db_connection()
    try:
        cur = conn.execute(
            "SELECT id, email, username FROM users WHERE id = ? AND username = ?",
            (uid, username),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        return row
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()


def username_is_valid(username: str) -> bool:
    return bool(re.fullmatch(r"^[A-Za-z0-9_]{3,32}$", username))


@app.post(
    "/register",
    summary="User registration",
    description="Register a new user with email, username and password.",
    status_code=201,
)
def register(request: RegisterRequest):
    # Validate username format explicitly (redundant with Pydantic regex, but defensive)
    if not username_is_valid(request.username):
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    conn = get_db_connection()
    try:
        # Check for existing email or username
        cur = conn.execute("SELECT id FROM users WHERE email = ? OR username = ?", (request.email, request.username))
        exists = cur.fetchone()
        if exists:
            raise HTTPException(status_code=400, detail="Email already in use or invalid data")

        password_hash = pbkdf2_sha256.hash(request.password)
        now_str = datetime.datetime.utcnow().isoformat()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (request.email, request.username, password_hash, now_str),
        )
        return {"message": "Registration successful"}
    except sqlite3.Error:
        # Likely constraint violation or db error
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    finally:
        conn.close()


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
    status_code=200,
)
def login(request: LoginRequest):
    conn = get_db_connection()
    try:
        cur = conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (request.email,),
        )
        row = cur.fetchone()
        # Use same message for invalid email or password to prevent user enumeration
        if not row:
            raise HTTPException(status_code=401, detail="Invalid email or password")
        password_hash = row["password_hash"]
        if not pbkdf2_sha256.verify(request.password, password_hash):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        token = create_jwt_token(row["id"], row["username"], row["email"])
        return {"token": token, "message": "Login successful"}
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
    status_code=200,
)
def set_secret(payload: SetSecretRequest, current_user: sqlite3.Row = Depends(get_current_user)):
    # Authorization: ensure the token owner matches the provided username (CWE-863 mitigation)
    if payload.username != current_user["username"]:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        # Ensure the user exists (it does, via current_user)
        user_id = current_user["id"]
        now_str = datetime.datetime.utcnow().isoformat()

        # Try to update; if no existing secret row, insert
        cur = conn.execute(
            "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
            (payload.secret, now_str, user_id),
        )
        if cur.rowcount == 0:
            conn.execute(
                "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
                (user_id, payload.secret, now_str),
            )

        return {"message": "Secret has been set successfully"}
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
    status_code=200,
)
def get_secret(username: str = Query(..., min_length=3, max_length=32), current_user: sqlite3.Row = Depends(get_current_user)):
    # Authorization: only allow users to retrieve their own secret (CWE-284 and CWE-863 mitigation)
    if username != current_user["username"]:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (current_user["id"],))
        row = cur.fetchone()
        # If secret not set, return empty string to conform to schema (200 with 'secret')
        secret_value = row["secret"] if row else ""
        return {"secret": secret_value}
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()


# Custom exception handlers to align response bodies with the OpenAPI schema
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Convert HTTPException to the expected schema: {"message": string}
    detail = exc.detail if isinstance(exc.detail, str) else "Internal server error"
    return JSONResponse(status_code=exc.status_code, content={"message": detail})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Generic handler for unexpected errors (CWE-703 mitigation)
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# Override OpenAPI schema to include security scheme and global security as specified
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Secret Storage",
        version="1.0.0",
        description="A secure cloud storage app for string secrets.",
        routes=app.routes,
    )
    # Add bearerAuth security scheme
    openapi_schema.setdefault("components", {}).setdefault("securitySchemes", {})["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Set global security requirement
    openapi_schema["security"] = [{"bearerAuth": []}]
    # Ensure /register and /login have security: []
    paths = openapi_schema.get("paths", {})
    if "/register" in paths and "post" in paths["/register"]:
        paths["/register"]["post"]["security"] = []
    if "/login" in paths and "post" in paths["/login"]:
        paths["/login"]["post"]["security"] = []

    # Add tags as specified
    openapi_schema["tags"] = [
        {"name": "Authentication", "description": "Operations related to user authentication"},
    ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000 without streaming responses
    uvicorn.run(app, host="0.0.0.0", port=5000)