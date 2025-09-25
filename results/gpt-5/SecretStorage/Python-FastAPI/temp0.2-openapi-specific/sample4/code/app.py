import os
import sqlite3
import secrets as pysecrets
from datetime import datetime, timedelta
from typing import Optional

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, constr
from passlib.hash import pbkdf2_sha256
import jwt

# App configuration
APP_TITLE = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"
OPENAPI_VERSION = "3.0.3"

DB_PATH = "db.sqlite3"
SECRET_KEY = os.getenv("APP_SECRET") or pysecrets.token_urlsafe(64)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    openapi_version=OPENAPI_VERSION,
)


# ---- Database utilities ----
def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
    except sqlite3.Error:
        # Ignore PRAGMA errors, but use defaults
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
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


# ---- Models ----
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: constr(strip_whitespace=True, min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_]+$") = Field(
        ..., example="user1"
    )
    password: constr(min_length=8, max_length=128) = Field(..., example="newUserPassword")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: constr(min_length=8, max_length=128) = Field(..., example="pass1")


class SetSecretRequest(BaseModel):
    username: constr(strip_whitespace=True, min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_]+$") = Field(
        ..., example="user1"
    )
    secret: constr(strip_whitespace=True, min_length=1, max_length=8192) = Field(..., example="mySecret")


# ---- Security utilities ----
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def extract_bearer_token(request: Request) -> Optional[str]:
    auth = request.headers.get("Authorization")
    if not auth:
        return None
    parts = auth.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# ---- Helper DB operations ----
def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> int:
    cur = conn.execute(
        "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
        (email, username, password_hash),
    )
    conn.commit()
    return cur.lastrowid


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    conn.execute(
        """
        INSERT INTO secrets (user_id, secret, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id) DO UPDATE SET
            secret = excluded.secret,
            updated_at = CURRENT_TIMESTAMP
        """,
        (user_id, secret),
    )
    conn.commit()


def get_secret_for_user(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    return row["secret"] if row else None


# ---- Routes ----
@app.post(
    "/register",
    status_code=201,
    summary="User registration",
    tags=["Authentication"],
)
async def register(payload: RegisterRequest):
    # Basic password strength check: require at least one letter and one digit
    pwd = payload.password
    if not any(c.isalpha() for c in pwd) or not any(c.isdigit() for c in pwd):
        return JSONResponse(
            status_code=400,
            content={"message": "Email already in use or invalid data"},
        )

    conn = get_db_connection()
    try:
        existing_email = get_user_by_email(conn, payload.email)
        if existing_email is not None:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        existing_username = get_user_by_username(conn, payload.username)
        if existing_username is not None:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        password_hash = pbkdf2_sha256.hash(payload.password)
        create_user(conn, payload.email.lower(), payload.username, password_hash)
        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except sqlite3.Error:
        # Handle unexpected DB errors
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    finally:
        conn.close()


@app.post(
    "/login",
    summary="User login",
    tags=["Authentication"],
)
async def login(payload: LoginRequest):
    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, payload.email.lower())
        # Do not reveal whether the email exists; generic error message
        if not user or not pbkdf2_sha256.verify(payload.password, user["password_hash"]):
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

        token_payload = {
            "uid": int(user["id"]),
            "username": user["username"],
            "email": user["email"],
            "iat": int(datetime.utcnow().timestamp()),
        }
        token = create_access_token(token_payload)
        return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})
    except sqlite3.Error:
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
    finally:
        conn.close()


@app.post(
    "/set_secret",
    summary="Set secret",
)
async def set_secret(request: Request, payload: SetSecretRequest):
    token = extract_bearer_token(request)
    if not token:
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    decoded = decode_token(token)
    if not decoded:
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Authorization: user can only set their own secret (CWE-284, CWE-863)
    if decoded.get("username") != payload.username:
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, payload.username)
        if not user:
            # Even if user not found, do not reveal; treat as invalid token to avoid enumeration
            return JSONResponse(
                status_code=401,
                content={"message": "Invalid authentication token"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        upsert_secret(conn, int(user["id"]), payload.secret)
        return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})
    except sqlite3.Error:
        # Handle unexpected DB errors gracefully
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    finally:
        conn.close()


@app.get(
    "/get_secret",
    summary="Get secret",
)
async def get_secret(request: Request, username: str):
    token = extract_bearer_token(request)
    if not token:
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    decoded = decode_token(token)
    if not decoded:
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Authorization: user can only get their own secret (CWE-284, CWE-863)
    if decoded.get("username") != username:
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, username)
        if not user:
            # Avoid revealing whether the user exists
            return JSONResponse(
                status_code=401,
                content={"message": "Invalid authentication token"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        secret_value = get_secret_for_user(conn, int(user["id"]))
        # If no secret is set, return an empty string to match schema type
        return JSONResponse(status_code=200, content={"secret": secret_value or ""})
    except sqlite3.Error:
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    finally:
        conn.close()


# ---- Startup ----
@app.on_event("startup")
def on_startup():
    init_db()


if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000 without using streaming responses
    uvicorn.run(app, host="0.0.0.0", port=5000)