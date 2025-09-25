import os
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn
import secrets as std_secrets

DB_PATH = "db.sqlite3"
APP_SECRET = os.environ.get("APP_SECRET") or std_secrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = 60


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_db_connection() -> sqlite3.Connection:
    # Create a new connection per request to avoid concurrency issues
    conn = sqlite3.connect(DB_PATH, isolation_level=None, timeout=5)
    conn.row_factory = sqlite3.Row
    with conn:
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db() -> None:
    with closing(get_db_connection()) as conn, conn:
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
                secret_text TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> int:
    cur = conn.execute(
        "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (email, username, password_hash, utc_now_iso()),
    )
    return cur.lastrowid


def get_secret_by_user_id(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret_text FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    return row["secret_text"] if row else None


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret_text: str) -> None:
    # Try update first, then insert if not exists
    cur = conn.execute(
        "UPDATE secrets SET secret_text = ?, updated_at = ? WHERE user_id = ?",
        (secret_text, utc_now_iso(), user_id),
    )
    if cur.rowcount == 0:
        conn.execute(
            "INSERT INTO secrets (user_id, secret_text, updated_at) VALUES (?, ?, ?)",
            (user_id, secret_text, utc_now_iso()),
        )


def create_access_token(user_id: int, username: str) -> str:
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "exp": int((datetime.now(timezone.utc) + timedelta(minutes=JWT_EXP_MINUTES)).timestamp()),
        "iss": "secret-storage",
        "jti": std_secrets.token_urlsafe(16),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    # PyJWT may return bytes in old versions, but here it returns str; ensure str
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


class RegisterRequest(BaseModel):
    email: EmailStr = Field(examples=["newuser@example.com"])
    username: str = Field(min_length=3, max_length=50, examples=["user1"])
    password: str = Field(min_length=8, max_length=128, examples=["newUserPassword"])


class RegisterResponse(BaseModel):
    message: str = Field(examples=["Registration successful"])


class LoginRequest(BaseModel):
    email: EmailStr = Field(examples=["user@example.com"])
    password: str = Field(min_length=8, max_length=128, examples=["mySecretPassword"])


class LoginResponse(BaseModel):
    token: str = Field(examples=["jwt-token-abc123"])
    message: str = Field(examples=["Login successful"])


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, examples=["user1"])
    secret: str = Field(min_length=1, max_length=4096, examples=["mySecret"])


class SetSecretResponse(BaseModel):
    message: str = Field(examples=["Secret has been set successfully"])


class GetSecretResponse(BaseModel):
    secret: str = Field(examples=["The secret associated with the provided details"])


app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


@app.on_event("startup")
def on_startup():
    try:
        init_db()
    except Exception:
        # Fail-safe: if DB initialization fails, raise to avoid undefined state.
        raise


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Handle unexpected errors without leaking internal details (CWE-703).
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


def verify_token_and_get_user(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM], options={"require": ["exp", "iat", "sub"]})
        user_id_str = payload.get("sub")
        username_claim = payload.get("username")
        if not user_id_str or not username_claim:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        user_id = int(user_id_str)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except (ValueError, TypeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    with closing(get_db_connection()) as conn:
        cur = conn.execute("SELECT id, email, username FROM users WHERE id = ?", (user_id,))
        user_row = cur.fetchone()
        if not user_row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        # Additional check: ensure the username in token still matches DB to prevent stale tokens after rename.
        if user_row["username"] != username_claim:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        return {"id": user_row["id"], "email": user_row["email"], "username": user_row["username"]}


def get_bearer_token_from_header(request: Request) -> str:
    auth = request.headers.get("Authorization") or ""
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    token = auth.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    return token


def get_current_user(request: Request) -> dict:
    # Extract and verify JWT, fetch current user
    token = get_bearer_token_from_header(request)
    return verify_token_and_get_user(token)


@app.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(req: RegisterRequest):
    email = req.email.lower().strip()
    username = req.username.strip()
    password = req.password

    # Basic validation and normalization
    if "@" not in email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
    if not username.isascii():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
    if " " in username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})

    password_hash = pbkdf2_sha256.hash(password)

    with closing(get_db_connection()) as conn, conn:
        # Check duplicates first to give clear errors without relying solely on IntegrityError
        existing_email = get_user_by_email(conn, email)
        existing_username = get_user_by_username(conn, username)
        if existing_email or existing_username:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
        try:
            create_user(conn, email, username, password_hash)
        except sqlite3.IntegrityError:
            # In case of race condition or constraint violation
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})

    return {"message": "Registration successful"}


@app.post(
    "/login",
    response_model=LoginResponse,
)
def login(req: LoginRequest):
    email = req.email.lower().strip()
    password = req.password

    with closing(get_db_connection()) as conn:
        user = get_user_by_email(conn, email)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
        password_hash = user["password_hash"]
        try:
            verified = pbkdf2_sha256.verify(password, password_hash)
        except Exception:
            # Handle unexpected verification errors securely
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
        if not verified:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

        token = create_access_token(user_id=int(user["id"]), username=user["username"])

    return {"token": token, "message": "Login successful"}


@app.post(
    "/set_secret",
    response_model=SetSecretResponse,
)
def set_secret(req: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    # Authorization enforcement: user can only set their own secret (CWE-284, CWE-863)
    if req.username.strip() != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    with closing(get_db_connection()) as conn, conn:
        upsert_secret(conn, current_user["id"], req.secret.strip())

    return {"message": "Secret has been set successfully"}


@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
)
def get_secret(username: str, current_user: dict = Depends(get_current_user)):
    # Authorization enforcement: user can only read their own secret (CWE-284, CWE-863)
    if username.strip() != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    with closing(get_db_connection()) as conn:
        secret_text = get_secret_by_user_id(conn, current_user["id"])
        if secret_text is None:
            # Spec does not define 404; return empty secret
            return {"secret": ""}

    return {"secret": secret_text}


if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000 without reload and without streaming responses.
    uvicorn.run(app, host="0.0.0.0", port=5000)