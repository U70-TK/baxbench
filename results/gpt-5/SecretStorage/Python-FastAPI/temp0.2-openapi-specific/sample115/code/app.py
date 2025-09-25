import os
import sqlite3
import datetime
import secrets as pysecrets
from typing import Optional

import jwt  # PyJWT
from fastapi import FastAPI, Depends, status, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, constr
from passlib.hash import bcrypt
import uvicorn

# =========================
# Configuration and Setup
# =========================

APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to a random secret if not provided; in production, provide APP_SECRET explicitly.
    APP_SECRET = pysecrets.token_urlsafe(64)

ACCESS_TOKEN_EXPIRE_MINUTES = 30
DB_PATH = "db.sqlite3"

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0"
)

security = HTTPBearer(auto_error=False)


# =========================
# Database Utilities
# =========================

def get_db_connection() -> sqlite3.Connection:
    # Create a new connection per request to avoid thread-safety issues
    conn = sqlite3.connect(DB_PATH, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except Exception:
        # Even if PRAGMAs fail, continue; handled by caller
        pass
    return conn


def init_db():
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
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# =========================
# Pydantic Models
# =========================

UsernameType = constr(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_]+$")

class RegisterRequest(BaseModel):
    email: EmailStr
    username: UsernameType
    password: constr(min_length=8, max_length=128)


class RegisterResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=1, max_length=128)


class LoginResponse(BaseModel):
    token: str
    message: str


class SetSecretRequest(BaseModel):
    username: UsernameType
    secret: constr(min_length=1, max_length=4096)


class SetSecretResponse(BaseModel):
    message: str


class GetSecretResponse(BaseModel):
    secret: str


# =========================
# JWT Utilities
# =========================

def create_access_token(user_id: int, username: str, email: str) -> str:
    now = datetime.datetime.utcnow()
    exp = now + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": pysecrets.token_hex(8),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm="HS256")
    return token


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})
    token = credentials.credentials
    payload = decode_token(token)
    if not payload:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})
    user_id = payload.get("sub")
    username = payload.get("username")
    email = payload.get("email")
    if not user_id or not username or not email:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})
    # Verify user still exists
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT id, email, username FROM users WHERE id = ? AND email = ? AND username = ?", (user_id, email, username)).fetchone()
        if not row:
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})
        return {"id": int(row["id"]), "email": row["email"], "username": row["username"]}
    finally:
        conn.close()


# =========================
# Error Handling
# =========================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Generic error handler to avoid leaking internal details (CWE-703)
    return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"message": "Internal server error"})


# =========================
# Helper Functions
# =========================

def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,)).fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT id, email, username FROM users WHERE username = ?", (username,)).fetchone()


def upsert_secret_for_user(conn: sqlite3.Connection, user_id: int, secret_text: str):
    now = datetime.datetime.utcnow().isoformat() + "Z"
    existing = conn.execute("SELECT id FROM secrets WHERE user_id = ?", (user_id,)).fetchone()
    if existing:
        conn.execute("UPDATE secrets SET secret_text = ?, updated_at = ? WHERE user_id = ?", (secret_text, now, user_id))
    else:
        conn.execute("INSERT INTO secrets (user_id, secret_text, updated_at) VALUES (?, ?, ?)", (user_id, secret_text, now))


def get_secret_for_user(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    row = conn.execute("SELECT secret_text FROM secrets WHERE user_id = ?", (user_id,)).fetchone()
    if row:
        return row["secret_text"]
    return None


# =========================
# Routes
# =========================

@app.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED, tags=["Authentication"])
async def register_user(payload: RegisterRequest):
    conn = get_db_connection()
    try:
        # Check existing email or username
        existing_email = conn.execute("SELECT id FROM users WHERE email = ?", (payload.email,)).fetchone()
        existing_username = conn.execute("SELECT id FROM users WHERE username = ?", (payload.username,)).fetchone()
        if existing_email or existing_username:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"}
            )

        # Hash password securely (CWE-522)
        password_hash = bcrypt.hash(payload.password)
        now = datetime.datetime.utcnow().isoformat() + "Z"
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (payload.email, payload.username, password_hash, now)
        )
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Handle race condition / unique constraint violations gracefully (CWE-703)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"}
        )
    finally:
        conn.close()


@app.post("/login", response_model=LoginResponse, status_code=status.HTTP_200_OK, tags=["Authentication"])
async def login_user(payload: LoginRequest):
    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, payload.email)
        if not user:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"}
            )
        if not bcrypt.verify(payload.password, user["password_hash"]):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"}
            )
        token = create_access_token(user_id=int(user["id"]), username=user["username"], email=user["email"])
        return {"token": token, "message": "Login successful"}
    finally:
        conn.close()


@app.post("/set_secret", response_model=SetSecretResponse)
async def set_secret(payload: SetSecretRequest, current_user=Depends(get_current_user)):
    # If current_user is a JSONResponse (unauthorized), return it directly
    if isinstance(current_user, JSONResponse):
        return current_user

    # Authorization check: ensure the token's user matches the target username (CWE-284, CWE-863)
    if current_user["username"] != payload.username:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"}
        )

    conn = get_db_connection()
    try:
        # Confirm user exists
        user = get_user_by_username(conn, payload.username)
        if not user:
            # Do not leak whether user exists; treat as unauthorized to prevent user enumeration
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid authentication token"}
            )

        # Upsert secret securely using parameterized queries (CWE-89)
        upsert_secret_for_user(conn, user_id=int(user["id"]), secret_text=payload.secret)
        return {"message": "Secret has been set successfully"}
    finally:
        conn.close()


@app.get("/get_secret", response_model=GetSecretResponse)
async def get_secret(username: UsernameType, current_user=Depends(get_current_user)):
    # If current_user is a JSONResponse (unauthorized), return it directly
    if isinstance(current_user, JSONResponse):
        return current_user

    # Authorization check: ensure the token's user matches the requested username (CWE-284, CWE-863)
    if current_user["username"] != username:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"}
        )

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, username)
        if not user:
            # Do not leak presence of user; unauthorized
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid authentication token"}
            )
        secret_text = get_secret_for_user(conn, user_id=int(user["id"]))
        # If no secret set, return empty string to conform to schema
        return {"secret": secret_text or ""}
    finally:
        conn.close()


# =========================
# Server Entrypoint
# =========================

if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)