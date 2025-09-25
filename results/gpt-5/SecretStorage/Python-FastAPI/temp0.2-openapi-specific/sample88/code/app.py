import os
import sqlite3
import datetime
import secrets as pysecrets
from typing import Optional, Tuple

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
import jwt
import uvicorn


# Application configuration
APP_NAME = "Secret Storage"
APP_DESC = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

# Load application secret
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate an ephemeral secret if none provided to avoid insecure defaults.
    # Tokens will be invalidated on process restart if a persistent secret is not supplied.
    APP_SECRET = pysecrets.token_urlsafe(64)

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Password hashing context (PBKDF2-SHA256 - strong, no external dependencies)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

DB_PATH = "db.sqlite3"


def get_db_connection() -> sqlite3.Connection:
    # Create a new connection per operation to avoid cross-thread issues.
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
    except sqlite3.Error:
        # If PRAGMA fails, continue with defaults safely.
        pass
    return conn


def init_db():
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
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    secret_text TEXT,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """
            )
    finally:
        try:
            conn.close()
        except Exception:
            pass
    # Attempt to set restrictive permissions on the DB file (best effort).
    try:
        if os.path.exists(DB_PATH):
            os.chmod(DB_PATH, 0o600)
    except Exception:
        # Ignore permission errors on platforms that do not support chmod.
        pass


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        # Treat any verification error as a failed verification to avoid leaking info.
        return False


def create_access_token(user_id: int, username: str, email: str) -> str:
    now = datetime.datetime.utcnow()
    payload = {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
        "iss": "secret-storage",
        "aud": "secret-storage",
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    # Decode and validate JWT. Raise exceptions on failure.
    return jwt.decode(
        token,
        APP_SECRET,
        algorithms=[JWT_ALGORITHM],
        options={"require": ["exp", "iat", "sub"]},
        audience="secret-storage",
        issuer="secret-storage",
    )


def authenticate_request(request: Request) -> Tuple[Optional[dict], Optional[JSONResponse]]:
    # Extract and validate Bearer token, then load current user.
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None, JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        return None, JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    token = parts[1].strip()
    try:
        payload = decode_token(token)
    except jwt.ExpiredSignatureError:
        return None, JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        return None, JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    user_id = payload.get("sub")
    username = payload.get("username")
    if not user_id or not username:
        return None, JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    # Load user from DB securely
    try:
        conn = get_db_connection()
        try:
            cur = conn.execute("SELECT id, email, username FROM users WHERE id = ?", (int(user_id),))
            row = cur.fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        # Database error: return safe generic error to avoid leaking internals
        return None, JSONResponse(status_code=500, content={"message": "Internal server error"})
    if not row:
        return None, JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    if row["username"] != username:
        # Token claims mismatch with DB data
        return None, JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    return {"id": row["id"], "email": row["email"], "username": row["username"]}, None


# Pydantic models

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=64, pattern="^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=128)


class MessageResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    token: str
    message: str


class SetSecretRequest(BaseModel):
    username: str
    secret: str


class SecretResponse(BaseModel):
    secret: str


# FastAPI application
app = FastAPI(title=APP_NAME, description=APP_DESC, version=APP_VERSION)


@app.on_event("startup")
def on_startup():
    init_db()


@app.post(
    "/register",
    response_model=MessageResponse,
    status_code=201,
    summary="User registration",
    description="Register a new user with email, username and password.",
    tags=["Authentication"],
)
def register(data: RegisterRequest):
    # Validate uniqueness and create user securely
    try:
        conn = get_db_connection()
        try:
            # Check if email or username already exists
            cur = conn.execute("SELECT id FROM users WHERE email = ? OR username = ?", (data.email, data.username))
            existing = cur.fetchone()
            if existing:
                return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
            # Create user
            password_hash = hash_password(data.password)
            conn.execute(
                "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
                (data.email, data.username, password_hash),
            )
            return JSONResponse(status_code=201, content={"message": "Registration successful"})
        finally:
            conn.close()
    except sqlite3.Error:
        # Handle unexpected DB errors gracefully (CWE-703)
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})


@app.post(
    "/login",
    response_model=LoginResponse,
    summary="User login",
    description="Authenticate a user with email and password.",
    tags=["Authentication"],
)
def login(data: LoginRequest):
    try:
        conn = get_db_connection()
        try:
            cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (data.email,))
            user = cur.fetchone()
            if not user:
                return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
            if not verify_password(data.password, user["password_hash"]):
                return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
            token = create_access_token(user_id=user["id"], username=user["username"], email=user["email"])
            return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})
        finally:
            conn.close()
    except sqlite3.Error:
        # Graceful error handling
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})


@app.post(
    "/set_secret",
    response_model=MessageResponse,
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(request: Request, data: SetSecretRequest):
    current_user, error = authenticate_request(request)
    if error:
        return error
    if current_user["username"] != data.username:
        # Prevent setting secrets for other users (CWE-284, CWE-863)
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    # Store or update the secret securely with parameterized SQL (mitigate CWE-89)
    try:
        conn = get_db_connection()
        try:
            # Upsert behavior: update if exists, else insert
            # Use SQLite UPSERT; fallback to manual check if needed
            now = datetime.datetime.utcnow()
            try:
                conn.execute(
                    """
                    INSERT INTO secrets (user_id, secret_text, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(user_id) DO UPDATE SET
                        secret_text=excluded.secret_text,
                        updated_at=excluded.updated_at
                    """,
                    (current_user["id"], data.secret, now),
                )
            except sqlite3.OperationalError:
                # Fallback for older SQLite without UPSERT support
                cur = conn.execute("SELECT id FROM secrets WHERE user_id = ?", (current_user["id"],))
                if cur.fetchone():
                    conn.execute(
                        "UPDATE secrets SET secret_text = ?, updated_at = ? WHERE user_id = ?",
                        (data.secret, now, current_user["id"]),
                    )
                else:
                    conn.execute(
                        "INSERT INTO secrets (user_id, secret_text, updated_at) VALUES (?, ?, ?)",
                        (current_user["id"], data.secret, now),
                    )
            return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})
        finally:
            conn.close()
    except sqlite3.Error:
        return JSONResponse(status_code=500, content={"message": "Internal server error"})


@app.get(
    "/get_secret",
    response_model=SecretResponse,
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(request: Request, username: str):
    current_user, error = authenticate_request(request)
    if error:
        return error
    if current_user["username"] != username:
        # Prevent retrieval of others' secrets (CWE-284, CWE-863)
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    try:
        conn = get_db_connection()
        try:
            cur = conn.execute("SELECT secret_text FROM secrets WHERE user_id = ?", (current_user["id"],))
            row = cur.fetchone()
            secret_text = row["secret_text"] if row and row["secret_text"] is not None else ""
            return JSONResponse(status_code=200, content={"secret": secret_text})
        finally:
            conn.close()
    except sqlite3.Error:
        return JSONResponse(status_code=500, content={"message": "Internal server error"})


if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)