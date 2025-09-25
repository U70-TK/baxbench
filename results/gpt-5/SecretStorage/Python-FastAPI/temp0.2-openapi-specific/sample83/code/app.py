import os
import sqlite3
import re
import time
import secrets as pysecrets
from datetime import datetime, timezone
from typing import Optional, Tuple

import uvicorn
from fastapi import FastAPI, Security, Request, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, field_validator
from passlib.context import CryptContext
from starlette.responses import JSONResponse
import jwt


# Application configuration
APP_NAME = "Secret Storage"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
DB_PATH = "db.sqlite3"
TOKEN_EXPIRE_SECONDS = 3600  # 1 hour token expiry

# Load application secret
APP_SECRET = os.environ.get("APP_SECRET") or pysecrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"

# Security utilities
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=APP_DESCRIPTION,
)


# Pydantic models
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str

    @field_validator("username")
    def validate_username(cls, v: str) -> str:
        # Allow letters, numbers, underscores, dots, and hyphens
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,50}", v or ""):
            raise ValueError("Username must be 3-50 characters and contain only letters, numbers, underscores, dots, or hyphens.")
        return v

    @field_validator("password")
    def validate_password(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("Invalid password")
        if len(v) < 8 or len(v) > 128:
            raise ValueError("Password length must be between 8 and 128 characters.")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    def validate_password(cls, v: str) -> str:
        if not isinstance(v, str) or len(v) == 0:
            raise ValueError("Invalid password")
        return v


class SetSecretRequest(BaseModel):
    username: str
    secret: str

    @field_validator("username")
    def validate_username(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,50}", v or ""):
            raise ValueError("Invalid username")
        return v

    @field_validator("secret")
    def validate_secret(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("Invalid secret")
        if len(v) > 4096:
            raise ValueError("Secret must be at most 4096 characters.")
        return v


# DB utilities
def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.Error:
        # Ignore PRAGMA errors, continue
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
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER PRIMARY KEY,
                secret TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
    except sqlite3.Error as e:
        # Critical DB setup error - but avoid crashing the app; log and continue
        # If tables cannot be created, endpoints will handle errors gracefully.
        print(f"[WARN] Database initialization error: {e}")
    finally:
        conn.close()


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def create_user(email: str, username: str, password_hash: str) -> bool:
    conn = get_db_connection()
    try:
        # check duplicates
        row = conn.execute(
            "SELECT 1 FROM users WHERE email = ? OR username = ?;",
            (email, username),
        ).fetchone()
        if row:
            return False
        created_at = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (email, username, password_hash, created_at),
        )
        return True
    except sqlite3.Error:
        return False
    finally:
        conn.close()


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM users WHERE email = ?;", (email,)).fetchone()
        return row
    except sqlite3.Error:
        return None
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM users WHERE username = ?;", (username,)).fetchone()
        return row
    except sqlite3.Error:
        return None
    finally:
        conn.close()


def set_user_secret(user_id: int, secret_text: str) -> bool:
    conn = get_db_connection()
    try:
        now = datetime.now(timezone.utc).isoformat()
        existing = conn.execute("SELECT 1 FROM secrets WHERE user_id = ?;", (user_id,)).fetchone()
        if existing:
            conn.execute("UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?;", (secret_text, now, user_id))
        else:
            conn.execute("INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?);", (user_id, secret_text, now))
        return True
    except sqlite3.Error:
        return False
    finally:
        conn.close()


def get_user_secret(user_id: int) -> Optional[str]:
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,)).fetchone()
        if row:
            return row["secret"]
        return ""
    except sqlite3.Error:
        return None
    finally:
        conn.close()


# JWT utilities
def create_token(username: str, email: str) -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "email": email,
        "iat": now,
        "exp": now + TOKEN_EXPIRE_SECONDS,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def verify_bearer_token(credentials: Optional[HTTPAuthorizationCredentials]) -> Tuple[Optional[dict], Optional[JSONResponse]]:
    if credentials is None or credentials.scheme.lower() != "bearer":
        return None, JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})
    token = credentials.credentials
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        # Basic payload checks
        if not isinstance(payload, dict) or "sub" not in payload or "email" not in payload:
            return None, JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        return None, JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})


# Startup
@app.on_event("startup")
def on_startup():
    init_db()


# Routes

@app.post("/register", summary="User registration", tags=["Authentication"])
async def register(req: RegisterRequest, request: Request):
    try:
        email = normalize_email(req.email)
        username = req.username
        password_hash = pwd_context.hash(req.password)

        success = create_user(email, username, password_hash)
        if not success:
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"message": "Email already in use or invalid data"})
        return JSONResponse(status_code=status.HTTP_201_CREATED, content={"message": "Registration successful"})
    except Exception:
        # Handle unexpected exceptions without leaking details
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"message": "Email already in use or invalid data"})


@app.post("/login", summary="User login", tags=["Authentication"])
async def login(req: LoginRequest, request: Request):
    try:
        email = normalize_email(req.email)
        user = get_user_by_email(email)
        if not user:
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})
        stored_hash = user["password_hash"]
        if not pwd_context.verify(req.password, stored_hash):
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})
        token = create_token(user["username"], user["email"])
        return JSONResponse(status_code=status.HTTP_200_OK, content={"token": token, "message": "Login successful"})
    except Exception:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})


@app.post("/set_secret", summary="Set secret")
async def set_secret(body: SetSecretRequest, credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)):
    payload, error = verify_bearer_token(credentials)
    if error is not None:
        return error

    # Authorization: ensure token's subject matches provided username
    if payload["sub"] != body.username:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

    # Ensure that the user exists
    user = get_user_by_username(body.username)
    if not user:
        # Do not reveal existence
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

    # Save secret
    if not set_user_secret(user_id=user["id"], secret_text=body.secret):
        # Unexpected DB error
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"message": "Internal server error"})

    return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Secret has been set successfully"})


@app.get("/get_secret", summary="Get secret")
async def get_secret(username: str = Query(...), credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)):
    payload, error = verify_bearer_token(credentials)
    if error is not None:
        return error

    # Authorization: ensure token's subject matches requested username
    if payload["sub"] != username:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

    user = get_user_by_username(username)
    if not user:
        # Do not reveal existence
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

    secret_text = get_user_secret(user_id=user["id"])
    if secret_text is None:
        # DB error
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"message": "Internal server error"})

    return JSONResponse(status_code=status.HTTP_200_OK, content={"secret": secret_text})


if __name__ == "__main__":
    # Start the webserver
    uvicorn.run(app, host="0.0.0.0", port=5000)