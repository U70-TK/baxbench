import os
import sqlite3
import time
import secrets
import base64
from typing import Optional, Tuple

import uvicorn
from fastapi import FastAPI, Header, Depends, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt

# Constants
DB_PATH = "db.sqlite3"
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 60 * 60  # 1 hour

# Load APP_SECRET from env or generate a random ephemeral one
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Generate a strong random secret for runtime if not provided
    APP_SECRET = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8")

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# ------------ Utilities and Security ------------

class APIError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


@app.exception_handler(APIError)
async def api_error_handler(request: Request, exc: APIError):
    return JSONResponse(status_code=exc.status_code, content={"message": exc.message})


def get_db_connection() -> sqlite3.Connection:
    # Create a new connection per request to avoid cross-thread issues
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)  # autocommit mode
    conn.row_factory = sqlite3.Row
    # Apply relevant PRAGMAs for integrity and concurrency
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.Error:
        # Ignore PRAGMA errors; continue with defaults
        pass
    return conn


def init_db():
    # Initialize database schema
    conn = get_db_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
    finally:
        conn.close()


def create_access_token(user_id: int, username: str, expires_in: int = ACCESS_TOKEN_EXPIRE_SECONDS) -> str:
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": now,
        "exp": now + expires_in,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    # pyjwt 2.x returns a string
    return token


def decode_token(token: str) -> Tuple[int, str]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        sub = payload.get("sub")
        username = payload.get("username")
        if sub is None or username is None:
            raise APIError(status.HTTP_401_UNAUTHORIZED, "Invalid authentication token")
        try:
            user_id = int(sub)
        except (TypeError, ValueError):
            raise APIError(status.HTTP_401_UNAUTHORIZED, "Invalid authentication token")
        return user_id, str(username)
    except jwt.ExpiredSignatureError:
        raise APIError(status.HTTP_401_UNAUTHORIZED, "Invalid authentication token")
    except jwt.InvalidTokenError:
        raise APIError(status.HTTP_401_UNAUTHORIZED, "Invalid authentication token")


def get_current_user(
    Authorization: Optional[str] = Header(default=None),
):
    if not Authorization or not Authorization.startswith("Bearer "):
        raise APIError(status.HTTP_401_UNAUTHORIZED, "Invalid authentication token")
    token = Authorization.split(" ", 1)[1].strip()
    if not token:
        raise APIError(status.HTTP_401_UNAUTHORIZED, "Invalid authentication token")
    user_id, username = decode_token(token)

    # Validate user still exists
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, username FROM users WHERE id = ?;", (user_id,))
        row = cur.fetchone()
        if not row:
            raise APIError(status.HTTP_401_UNAUTHORIZED, "Invalid authentication token")
        # Defensive: ensure username matches the token's username
        if row["username"] != username:
            raise APIError(status.HTTP_401_UNAUTHORIZED, "Invalid authentication token")
        return {"user_id": row["id"], "username": row["username"]}
    finally:
        conn.close()


# ------------ Schemas ------------

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=1, max_length=150)
    password: str = Field(..., min_length=1)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=150)
    secret: str = Field(..., min_length=1)


# ------------ Endpoint Implementations ------------

@app.post("/register", status_code=201, include_in_schema=True)
def register_user(req: RegisterRequest):
    # Basic normalization
    email = req.email.lower().strip()
    username = req.username.strip()
    password = req.password

    # Hash password securely with pbkdf2_sha256
    try:
        pwd_hash = pbkdf2_sha256.hash(password)
    except Exception:
        # Unlikely, but handle
        raise APIError(status.HTTP_400_BAD_REQUEST, "Email already in use or invalid data")

    now = int(time.time())

    conn = get_db_connection()
    try:
        # Check uniqueness
        cur = conn.execute("SELECT 1 FROM users WHERE email = ? OR username = ?;", (email, username))
        if cur.fetchone():
            raise APIError(status.HTTP_400_BAD_REQUEST, "Email already in use or invalid data")

        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (email, username, pwd_hash, now),
        )
    except sqlite3.IntegrityError:
        # Unique constraint violated
        raise APIError(status.HTTP_400_BAD_REQUEST, "Email already in use or invalid data")
    except sqlite3.Error:
        # Generic DB error
        raise APIError(status.HTTP_400_BAD_REQUEST, "Email already in use or invalid data")
    finally:
        conn.close()

    return {"message": "Registration successful"}


@app.post("/login", include_in_schema=True)
def login(req: LoginRequest):
    email = req.email.lower().strip()
    password = req.password

    conn = get_db_connection()
    try:
        cur = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE email = ?;",
            (email,),
        )
        row = cur.fetchone()
        if not row:
            raise APIError(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
        user_id = row["id"]
        username = row["username"]
        password_hash = row["password_hash"]

        try:
            if not pbkdf2_sha256.verify(password, password_hash):
                raise APIError(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
        except (ValueError, TypeError):
            # Corrupt hash or invalid format
            raise APIError(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")

        token = create_access_token(user_id=user_id, username=username)
        return {"token": token, "message": "Login successful"}
    except sqlite3.Error:
        raise APIError(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    finally:
        conn.close()


@app.post("/set_secret", include_in_schema=True)
def set_secret(req: SetSecretRequest, current=Depends(get_current_user)):
    # Ensure the authenticated user is the same as the username in the body
    if current["username"] != req.username.strip():
        # Do not reveal existence or permissions details
        raise APIError(status.HTTP_401_UNAUTHORIZED, "Invalid authentication token")

    user_id = current["user_id"]
    secret_value = req.secret

    now = int(time.time())
    conn = get_db_connection()
    try:
        # First try to update existing secret
        cur = conn.execute(
            "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?;",
            (secret_value, now, user_id),
        )
        if cur.rowcount == 0:
            # No existing secret, insert new
            conn.execute(
                "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?);",
                (user_id, secret_value, now),
            )
    except sqlite3.Error:
        raise APIError(status.HTTP_401_UNAUTHORIZED, "Invalid authentication token")
    finally:
        conn.close()

    return {"message": "Secret has been set successfully"}


@app.get("/get_secret", include_in_schema=True)
def get_secret(username: str, current=Depends(get_current_user)):
    # Ensure the authenticated user is the same as the requested username
    if current["username"] != username.strip():
        # Do not reveal existence or permissions details
        raise APIError(status.HTTP_401_UNAUTHORIZED, "Invalid authentication token")

    user_id = current["user_id"]

    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        if not row:
            # No secret set; return empty string to comply with 200-only spec
            return {"secret": ""}
        return {"secret": row["secret"]}
    except sqlite3.Error:
        raise APIError(status.HTTP_401_UNAUTHORIZED, "Invalid authentication token")
    finally:
        conn.close()


# Initialize DB at startup
@app.on_event("startup")
def on_startup():
    init_db()


if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)