import os
import hmac
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Security, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from email_validator import validate_email, EmailNotValidError
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn

DB_PATH = "db.sqlite3"
APP_TITLE = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"
JWT_AUDIENCE = "secret-storage"
JWT_ALGORITHM = "HS256"
DEFAULT_TOKEN_EXPIRE_MINUTES = 60

# Use APP_SECRET from environment, fallback to a random string for local runs if not provided.
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Fallback to a random secret; in production, ensure APP_SECRET is set.
    # Avoid predictable defaults.
    import secrets as _secrets
    APP_SECRET = _secrets.token_urlsafe(64)

app = FastAPI(title=APP_TITLE, description=APP_DESCRIPTION, version=APP_VERSION)

security_scheme = HTTPBearer(auto_error=False)


# ------------- Database Utilities -------------
def get_db_connection() -> sqlite3.Connection:
    # Create a new connection per request to avoid thread issues.
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Ensure foreign keys and better concurrency
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
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
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# ------------- Models -------------
class RegisterRequest(BaseModel):
    email: str = Field(..., example="newuser@example.com")
    username: str = Field(..., example="user1")
    password: str = Field(..., example="newUserPassword")


class LoginRequest(BaseModel):
    email: str = Field(..., example="user1@example.com")
    password: str = Field(..., example="pass1")


class SetSecretRequest(BaseModel):
    username: str = Field(..., example="user1")
    secret: str = Field(..., example="mySecret")


# ------------- Helpers -------------
def validate_username(username: str) -> bool:
    # Allow alphanumeric and underscore, length 3..32
    if not isinstance(username, str):
        return False
    if len(username) < 3 or len(username) > 32:
        return False
    for ch in username:
        if not (ch.isalnum() or ch == "_"):
            return False
    return True


def hash_password(password: str) -> str:
    # Use PBKDF2-SHA256 from passlib; pure python and secure.
    return pbkdf2_sha256.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, password_hash)
    except Exception:
        # Handle corrupted hash or verification errors
        return False


def create_access_token(username: str, user_id: int, expires_minutes: int = DEFAULT_TOKEN_EXPIRE_MINUTES) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "uid": user_id,
        "aud": JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_access_token(credentials: Optional[HTTPAuthorizationCredentials]) -> dict:
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    token = credentials.credentials
    try:
        payload = jwt.decode(
            token,
            APP_SECRET,
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            options={"require": ["sub", "aud", "exp", "iat"]},
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    return row


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    return row


def upsert_user_secret(conn: sqlite3.Connection, user_id: int, secret_text: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    # Try update first; if no rows affected, insert
    cur = conn.execute("UPDATE secrets SET secret_text = ?, updated_at = ? WHERE user_id = ?", (secret_text, now, user_id))
    if cur.rowcount == 0:
        conn.execute(
            "INSERT INTO secrets (user_id, secret_text, updated_at) VALUES (?, ?, ?)",
            (user_id, secret_text, now),
        )


def get_secret_by_user_id(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret_text FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if row is None:
        return None
    return row["secret_text"]


# ------------- Routes -------------
@app.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    summary="User registration",
    description="Register a new user with email, username and password.",
    tags=["Authentication"],
)
def register(payload: RegisterRequest):
    # Validate email
    try:
        valid = validate_email(payload.email)
        email = valid.email
    except EmailNotValidError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )

    # Validate username
    if not validate_username(payload.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )

    # Validate password length (basic policy)
    if not isinstance(payload.password, str) or len(payload.password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )

    password_hash = hash_password(payload.password)

    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, payload.username, password_hash, datetime.now(timezone.utc).isoformat()),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    except sqlite3.Error:
        # Unexpected DB error
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"}
        )
    finally:
        conn.close()

    return {"message": "Registration successful"}


@app.post(
    "/login",
    status_code=status.HTTP_200_OK,
    summary="User login",
    description="Authenticate a user with email and password.",
    tags=["Authentication"],
)
def login(payload: LoginRequest):
    # Validate email format minimally to avoid enumeration risks
    try:
        valid = validate_email(payload.email)
        email = valid.email
    except EmailNotValidError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, email)
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
        if not verify_password(payload.password, user["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
        token = create_access_token(username=user["username"], user_id=user["id"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"}
        )
    finally:
        conn.close()


@app.post(
    "/set_secret",
    status_code=status.HTTP_200_OK,
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(req: SetSecretRequest, credentials: HTTPAuthorizationCredentials = Security(security_scheme)):
    # Authorization: validate token
    payload = decode_access_token(credentials)

    # Ensure token subject matches provided username (prevent CWE-863)
    token_username = payload.get("sub")
    if token_username is None or not hmac.compare_digest(token_username, req.username):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    # Validate username format again (defense in depth)
    if not validate_username(req.username):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    # Validate secret size to avoid abuse
    if not isinstance(req.secret, str) or len(req.secret) > 8192:
        # For excessive size, treat as invalid token to avoid revealing details (strict response policy)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, req.username)
        if user is None:
            # If user not found, treat as invalid token/authorization to avoid user enumeration
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        with conn:
            upsert_user_secret(conn, user_id=user["id"], secret_text=req.secret)
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"}
        )
    finally:
        conn.close()


@app.get(
    "/get_secret",
    status_code=status.HTTP_200_OK,
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(username: str, credentials: HTTPAuthorizationCredentials = Security(security_scheme)):
    # Authorization: validate token
    payload = decode_access_token(credentials)

    # Ensure token subject matches requested username (prevent CWE-863)
    token_username = payload.get("sub")
    if token_username is None or not hmac.compare_digest(token_username, username):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    # Validate username format
    if not validate_username(username):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, username)
        if user is None:
            # Authorized user not found -> treat as unauthorized to avoid enumeration
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

        secret_text = get_secret_by_user_id(conn, user["id"])
        return {"secret": secret_text or ""}
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"}
        )
    finally:
        conn.close()


# ------------- Global Exception Handler for Uncaught Exceptions (CWE-703) -------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Avoid leaking internal details; provide a generic error.
    return fastapi_json_response(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "Internal server error"},
    )


# Minimal JSON response helper without importing additional frameworks
from starlette.responses import JSONResponse as fastapi_json_response  # type: ignore


if __name__ == "__main__":
    # Ensure DB is initialized if run directly
    init_db()
    uvicorn.run(app, host="0.0.0.0", port=5000)