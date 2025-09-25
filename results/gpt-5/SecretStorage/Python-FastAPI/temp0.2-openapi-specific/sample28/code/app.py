import os
import sqlite3
import re
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Request, Body, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn

# -----------------------------------------------------------------------------
# Configuration & Security
# -----------------------------------------------------------------------------

APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fall back to a random ephemeral secret if not provided. This is not ideal for production,
    # but ensures the app can run; tokens will invalidate on restart.
    APP_SECRET = pysecrets.token_urlsafe(64)
    print("WARNING: APP_SECRET not set. Using an ephemeral secret for this session.")

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

DB_NAME = "db.sqlite3"


# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------

def get_db_connection() -> sqlite3.Connection:
    # Create a new connection per request to avoid threading issues with SQLite.
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    # Enforce foreign keys for referential integrity.
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    conn = get_db_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret_text TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        conn.commit()
    finally:
        conn.close()


def normalize_email(email: str) -> str:
    return email.strip().lower()


def is_valid_username(username: str) -> bool:
    # Allow alphanumerics, underscore, hyphen, dot; length 3-50
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{3,50}", username))


def create_access_token(*, subject: str, email: str) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": subject,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "type": "access",
        "jti": pysecrets.token_hex(16),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?;", (username,))
        row = cur.fetchone()
        return row
    except sqlite3.Error:
        return None


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?;", (email,))
        row = cur.fetchone()
        return row
    except sqlite3.Error:
        return None


# -----------------------------------------------------------------------------
# Pydantic Models
# -----------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., examples=["user1"])
    password: str = Field(..., min_length=8, examples=["newUserPassword"])

class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user1@example.com"])
    password: str = Field(..., min_length=8, examples=["pass1"])

class SetSecretRequest(BaseModel):
    username: str = Field(..., examples=["user1"])
    secret: str = Field(..., examples=["mySecret"])


# -----------------------------------------------------------------------------
# FastAPI Application
# -----------------------------------------------------------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    openapi_tags=[{"name": "Authentication", "description": "Operations related to user authentication"}],
)


@app.on_event("startup")
def on_startup():
    init_db()


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------

@app.post(
    "/register",
    summary="User registration",
    description="Register a new user with email, username and password.",
)
def register(
    payload: RegisterRequest = Body(
        ...,
        examples={
            "newUser": {
                "summary": "Sample new user",
                "value": {
                    "email": "newuser@example.com",
                    "username": "user1",
                    "password": "newUserPassword",
                },
            }
        },
    )
):
    conn = get_db_connection()
    try:
        email = normalize_email(payload.email)
        username = payload.username.strip()

        # Basic validation
        if not is_valid_username(username):
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        # Check if email or username already exists
        cur = conn.execute("SELECT id FROM users WHERE email = ? OR username = ?;", (email, username))
        exists = cur.fetchone()
        if exists:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        # Hash password securely (PBKDF2-SHA256)
        password_hash = pbkdf2_sha256.hash(payload.password)

        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (email, username, password_hash, now),
        )
        conn.commit()
        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except sqlite3.Error:
        # Graceful handling of unexpected DB errors
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    finally:
        conn.close()


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
)
def login(
    payload: LoginRequest = Body(
        ...,
        examples={
            "user1": {
                "summary": "Sample user #1",
                "value": {
                    "email": "user1@example.com",
                    "password": "pass1",
                },
            }
        },
    )
):
    conn = get_db_connection()
    try:
        email = normalize_email(payload.email)
        user = get_user_by_email(conn, email)
        if not user:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

        # Verify password
        try:
            valid = pbkdf2_sha256.verify(payload.password, user["password_hash"])
        except ValueError:
            # Handle malformed hashes gracefully
            valid = False

        if not valid:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

        token = create_access_token(subject=user["username"], email=user["email"])
        return {"token": token, "message": "Login successful"}
    except sqlite3.Error:
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
    finally:
        conn.close()


def get_token_from_header(request: Request) -> Optional[str]:
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        return None
    return auth[len("Bearer "):].strip()


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(
    request: Request,
    payload: SetSecretRequest = Body(
        ...,
        examples={
            "example1": {
                "summary": "Set a secret for user1",
                "value": {
                    "username": "user1",
                    "secret": "mySecret",
                },
            }
        },
    ),
):
    token = get_token_from_header(request)
    if not token:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    decoded = decode_token(token)
    if decoded is None:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    # Ensure the token subject matches the requested username to prevent cross-user access
    if decoded.get("sub") != payload.username:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, payload.username)
        if not user:
            # If user not found, treat as invalid token/username combo (do not reveal existence).
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

        now = datetime.now(timezone.utc).isoformat()

        # Try update first
        cur = conn.execute(
            "UPDATE secrets SET secret_text = ?, updated_at = ? WHERE user_id = ?;",
            (payload.secret, now, user["id"]),
        )
        if cur.rowcount == 0:
            # Insert if no existing secret
            conn.execute(
                "INSERT INTO secrets (user_id, secret_text, updated_at) VALUES (?, ?, ?);",
                (user["id"], payload.secret, now),
            )
        conn.commit()
        return {"message": "Secret has been set successfully"}
    except sqlite3.Error:
        # Graceful handling
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    finally:
        conn.close()


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(request: Request, username: str = Query(..., examples=["user1"])):
    token = get_token_from_header(request)
    if not token:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    decoded = decode_token(token)
    if decoded is None:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    # Enforce authorization: user can only access their own secret
    if decoded.get("sub") != username:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, username)
        if not user:
            # Obscure whether user exists
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

        cur = conn.execute("SELECT secret_text FROM secrets WHERE user_id = ?;", (user["id"],))
        row = cur.fetchone()
        secret_text = row["secret_text"] if row else ""
        return {"secret": secret_text}
    except sqlite3.Error:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# Server Entrypoint
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    # Run the application server
    uvicorn.run(app, host="0.0.0.0", port=5000)