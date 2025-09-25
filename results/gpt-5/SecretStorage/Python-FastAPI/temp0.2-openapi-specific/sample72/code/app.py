import os
import sqlite3
import logging
import time
from typing import Optional

from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
import jwt
import uvicorn

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secret-storage")

# Application secret for JWT
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Fallback: ephemeral secret if not provided (tokens will be invalid after restart)
    # In production, always provide APP_SECRET via environment securely.
    import secrets as _secrets
    APP_SECRET = _secrets.token_urlsafe(48)

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DB_PATH = "db.sqlite3"

# Password hashing context using a secure scheme without external dependencies
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def current_timestamp() -> int:
    return int(time.time())


def init_db() -> None:
    """
    Initialize the SQLite database and tables.
    """
    try:
        with sqlite3.connect(DB_PATH, timeout=30.0) as conn:
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA journal_mode = WAL;")
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
                    user_id INTEGER PRIMARY KEY,
                    secret TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
            conn.commit()
    except Exception as e:
        logger.exception("Failed to initialize database: %s", e)
        # Fail-fast if DB can't be initialized to avoid running with broken state.
        raise


def create_access_token(username: str, user_id: int, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    """
    Create a JWT access token with expiration.
    """
    now = current_timestamp()
    payload = {
        "sub": username,
        "uid": user_id,
        "iat": now,
        "exp": now + expires_minutes * 60,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def get_user_by_username(username: str) -> Optional[dict]:
    """
    Retrieve a user by username.
    """
    try:
        with sqlite3.connect(DB_PATH, timeout=30.0) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?;", (username,))
            row = cur.fetchone()
            return dict(row) if row else None
    except sqlite3.Error as e:
        logger.error("Database error in get_user_by_username: %s", e)
        return None


def get_user_by_email(email: str) -> Optional[dict]:
    """
    Retrieve a user by email.
    """
    try:
        with sqlite3.connect(DB_PATH, timeout=30.0) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?;", (email,))
            row = cur.fetchone()
            return dict(row) if row else None
    except sqlite3.Error as e:
        logger.error("Database error in get_user_by_email: %s", e)
        return None


def save_or_update_secret(user_id: int, secret_text: str) -> bool:
    """
    Insert or update a user's secret securely.
    """
    try:
        now = current_timestamp()
        with sqlite3.connect(DB_PATH, timeout=30.0) as conn:
            conn.execute(
                """
                INSERT INTO secrets(user_id, secret, created_at, updated_at)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret = excluded.secret,
                    updated_at = excluded.updated_at;
                """,
                (user_id, secret_text, now, now),
            )
            conn.commit()
        return True
    except sqlite3.Error as e:
        logger.error("Database error in save_or_update_secret: %s", e)
        return False


def get_secret_by_username(username: str) -> Optional[str]:
    """
    Retrieve a secret by username.
    """
    try:
        with sqlite3.connect(DB_PATH, timeout=30.0) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                """
                SELECT s.secret
                FROM secrets s
                JOIN users u ON s.user_id = u.id
                WHERE u.username = ?;
                """,
                (username,),
            )
            row = cur.fetchone()
            return row["secret"] if row else None
    except sqlite3.Error as e:
        logger.error("Database error in get_secret_by_username: %s", e)
        return None


# FastAPI app
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


# Exception handlers to ensure response objects use {"message": "..."} as per schema
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception: %s", exc)
    # CWE-703: General catch-all with sanitized output
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


from fastapi import HTTPException, status


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Return {"message": "..."} to match schema, not default {"detail": "..."}
    detail = exc.detail if isinstance(exc.detail, str) else "Error"
    return JSONResponse(status_code=exc.status_code, content={"message": detail})


# Dependency for authentication using Bearer JWT
async def get_current_user(request: Request) -> dict:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        # Missing or malformed Authorization header
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    token = auth_header.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        user_id = payload.get("uid")
        if not username or not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        user = get_user_by_username(username)
        if not user or user.get("id") != user_id:
            # Token does not correspond to an existing user
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except Exception as e:
        logger.error("Unexpected error in token processing: %s", e)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


# Request models
class RegisterRequest(BaseModel):
    email: EmailStr = Field(example="newuser@example.com")
    username: str = Field(min_length=3, max_length=32, example="user1")
    password: str = Field(min_length=5, max_length=128, example="newUserPassword")  # minimum 5 to accommodate example


class LoginRequest(BaseModel):
    email: EmailStr = Field(example="user@example.com")
    password: str = Field(min_length=5, max_length=128, example="mySecretPassword")


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32, example="user1")
    secret: str = Field(min_length=1, max_length=10000, example="mySecret")


@app.on_event("startup")
def on_startup():
    init_db()


@app.post(
    "/register",
    status_code=201,
    summary="User registration",
    description="Register a new user with email, username and password.",
    tags=["Authentication"],
)
async def register(payload: RegisterRequest):
    # Basic server-side validation of username characters for consistency
    # Allow alphanumeric, underscore, dot and dash
    import re

    if not re.fullmatch(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{2,31}$", payload.username):
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

    try:
        existing_email = get_user_by_email(payload.email)
        existing_username = get_user_by_username(payload.username)
        if existing_email or existing_username:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        password_hash = pwd_context.hash(payload.password)
        with sqlite3.connect(DB_PATH, timeout=30.0) as conn:
            conn.execute(
                "INSERT INTO users(email, username, password_hash, created_at) VALUES(?, ?, ?, ?);",
                (payload.email, payload.username, password_hash, current_timestamp()),
            )
            conn.commit()
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Unique constraint violation or similar
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    except Exception as e:
        logger.error("Error in registration: %s", e)
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
    tags=["Authentication"],
)
async def login(payload: LoginRequest):
    try:
        user = get_user_by_email(payload.email)
        if not user:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        if not pwd_context.verify(payload.password, user["password_hash"]):
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        token = create_access_token(username=user["username"], user_id=user["id"])
        return {"token": token, "message": "Login successful"}
    except Exception as e:
        logger.error("Error in login: %s", e)
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
async def set_secret(payload: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    # Authorization: ensure the username in payload matches the authenticated user
    if payload.username != current_user.get("username"):
        # CWE-863: Correct authorization check to prevent access to other users
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    try:
        ok = save_or_update_secret(current_user["id"], payload.secret)
        if not ok:
            # If DB operation failed, avoid leaking info
            return JSONResponse(status_code=500, content={"message": "Internal server error"})
        return {"message": "Secret has been set successfully"}
    except Exception as e:
        logger.error("Error in set_secret: %s", e)
        return JSONResponse(status_code=500, content={"message": "Internal server error"})


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
async def get_secret(username: str, current_user: dict = Depends(get_current_user)):
    # Authorization: ensure the query username matches the authenticated user
    if username != current_user.get("username"):
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    try:
        secret = get_secret_by_username(username)
        # If no secret set, return empty string for consistency; do not leak resource existence
        return {"secret": secret if secret is not None else ""}
    except Exception as e:
        logger.error("Error in get_secret: %s", e)
        return JSONResponse(status_code=500, content={"message": "Internal server error"})


if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)