import os
import sqlite3
import re
import hmac
import hashlib
import base64
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Request, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, ValidationError

import jwt  # pyjwt

# =========================
# Configuration and Security
# =========================

APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate a strong, ephemeral secret if not provided.
    # In production, always set APP_SECRET via environment variables.
    APP_SECRET = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

PASSWORD_HASH_ITERATIONS = 310_000
PASSWORD_SALT_BYTES = 16

DATABASE_FILE = "db.sqlite3"

# =========================
# Database Utilities
# =========================

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_FILE, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Enforce foreign key constraints in SQLite
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
            password_salt BLOB NOT NULL,
            password_hash BLOB NOT NULL,
            created_at TEXT NOT NULL
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            secret TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)
        conn.commit()
    finally:
        conn.close()

# Initialize DB at import time to ensure the file/tables exist even before startup
init_db()

# =========================
# Password Hashing (PBKDF2)
# =========================

def hash_password(password: str) -> Tuple[bytes, bytes]:
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    salt = os.urandom(PASSWORD_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS
    )
    return salt, dk

def verify_password(password: str, salt: bytes, expected_hash: bytes) -> bool:
    try:
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            PASSWORD_HASH_ITERATIONS
        )
        return hmac.compare_digest(candidate, expected_hash)
    except Exception:
        return False

# =========================
# JWT Utilities
# =========================

def create_access_token(user_id: int, username: str) -> str:
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
        "nbf": int(now.timestamp()),
        "jti": base64.urlsafe_b64encode(os.urandom(16)).decode("utf-8"),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

# =========================
# Schemas
# =========================

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=256)

class RegisterResponse(BaseModel):
    message: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=256)

class LoginResponse(BaseModel):
    token: str
    message: str

class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    secret: str = Field(..., min_length=0)

class SetSecretResponse(BaseModel):
    message: str

class GetSecretResponse(BaseModel):
    secret: str

# =========================
# Helpers for Users/Secrets
# =========================

USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,50}$")

def validate_username(username: str) -> bool:
    return bool(USERNAME_REGEX.fullmatch(username))

def user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
    return cur.fetchone()

def user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()

def user_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()

def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    now = datetime.now(tz=timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO secrets (user_id, secret, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            secret = excluded.secret,
            updated_at = excluded.updated_at
        """,
        (user_id, secret, now),
    )
    conn.commit()

def get_secret(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    return row["secret"] if row else None

# =========================
# Auth Dependency
# =========================

bearer_scheme = HTTPBearer(auto_error=False)

class AuthenticatedUser(BaseModel):
    id: int
    username: str
    email: EmailStr

async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)) -> AuthenticatedUser:
    if credentials is None or credentials.scheme.lower() != "bearer":
        # Do not leak details; align with documented 401 response
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    payload = decode_access_token(token)
    user_id = payload.get("sub")
    username = payload.get("username")
    if not user_id or not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    try:
        uid = int(user_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    conn = get_db_connection()
    try:
        user_row = user_by_id(conn, uid)
        if not user_row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        # Optional: verify username matches token claim
        if user_row["username"] != username:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        return AuthenticatedUser(id=user_row["id"], username=user_row["username"], email=user_row["email"])
    finally:
        conn.close()

# =========================
# FastAPI App
# =========================

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# =========================
# Routes
# =========================

@app.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED, tags=["Authentication"])
async def register(payload: RegisterRequest):
    # Basic input hardening
    email = payload.email.lower().strip()
    username = payload.username.strip()
    password = payload.password

    if not validate_username(username):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
    if len(password) < 8 or len(password) > 256:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})

    salt, pwd_hash = hash_password(password)
    conn = get_db_connection()
    try:
        now = datetime.now(tz=timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (email, username, password_salt, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
            (email, username, salt, pwd_hash, now),
        )
        conn.commit()
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Email or username already in use, or constraint violation
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
    except Exception:
        # Generic error handling with minimal leakage
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
    finally:
        conn.close()

@app.post("/login", response_model=LoginResponse, tags=["Authentication"])
async def login(payload: LoginRequest):
    email = payload.email.lower().strip()
    password = payload.password

    conn = get_db_connection()
    try:
        user = user_by_email(conn, email)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
        salt = user["password_salt"]
        pwd_hash = user["password_hash"]
        if not (isinstance(salt, (bytes, bytearray)) and isinstance(pwd_hash, (bytes, bytearray))):
            # Data corruption or unexpected types
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
        if not verify_password(password, salt, pwd_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
        token = create_access_token(user_id=user["id"], username=user["username"])
        return {"token": token, "message": "Login successful"}
    finally:
        conn.close()

@app.post("/set_secret", response_model=SetSecretResponse)
async def set_secret(payload: SetSecretRequest, current_user: AuthenticatedUser = Depends(get_current_user)):
    # Authorization: ensure the provided username matches the authenticated user
    if payload.username != current_user.username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    conn = get_db_connection()
    try:
        upsert_secret(conn, current_user.id, payload.secret)
        return {"message": "Secret has been set successfully"}
    finally:
        conn.close()

@app.get("/get_secret", response_model=GetSecretResponse)
async def get_secret_endpoint(username: str = Query(...), current_user: AuthenticatedUser = Depends(get_current_user)):
    # Authorization: ensure the requested username matches the authenticated user
    if username != current_user.username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    conn = get_db_connection()
    try:
        sec = get_secret(conn, current_user.id)
        return {"secret": sec if sec is not None else ""}
    finally:
        conn.close()

# =========================
# Exception Handlers
# =========================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Ensure the error response matches the OpenAPI examples where applicable
    detail = exc.detail
    # If detail is a dict with message, pass it through; else wrap it
    if isinstance(detail, dict) and "message" in detail:
        content = detail
    else:
        # Generic fallback message (avoid leaking internals)
        message = "Invalid authentication token" if exc.status_code == status.HTTP_401_UNAUTHORIZED else "Bad Request"
        content = {"message": message}
    return fastapi_json_response(content, status_code=exc.status_code)

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Do not leak internal details; respond with a generic 500.
    return fastapi_json_response({"message": "Internal Server Error"}, status_code=500)

# Helper to build JSON responses without using streaming
from fastapi.responses import JSONResponse
def fastapi_json_response(content: dict, status_code: int = 200) -> JSONResponse:
    return JSONResponse(content=content, status_code=status_code)

# =========================
# Startup Event (Ensure DB)
# =========================

@app.on_event("startup")
async def on_startup():
    # Re-run to ensure migrations exist in case runtime created db file
    init_db()

# =========================
# Main Entrypoint
# =========================

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)