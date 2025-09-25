import os
import re
import sqlite3
from datetime import datetime, timedelta
from typing import Optional, Dict

from fastapi import FastAPI, Depends, status, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from passlib.hash import pbkdf2_sha256
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError

# Constants and configuration
DB_PATH = "db.sqlite3"
JWT_ALGORITHM = "HS256"
APP_SECRET = os.environ.get("APP_SECRET") or os.urandom(32).hex()
TOKEN_EXPIRE_MINUTES = 60

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0"
)

bearer_security = HTTPBearer(auto_error=False)


# Exception handlers to match required response schemas
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Generic 500 handler to avoid leakage of internal details (CWE-703)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "Internal server error"}
    )


@app.exception_handler(jwt.PyJWTError)
async def jwt_exception_handler(request: Request, exc: jwt.PyJWTError):
    # Convert JWT errors to required 401 schema
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"message": "Invalid authentication token"}
    )


# Utility functions
def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    # Ensure foreign keys
    conn.execute("PRAGMA foreign_keys = ON;")
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
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
    finally:
        conn.close()


def normalize_username(username: str) -> str:
    # Normalize to lowercase for consistent uniqueness handling
    return username.strip().lower()


def is_valid_username(username: str) -> bool:
    # Limit to alphanumeric and underscores, 3-32 chars
    return bool(re.fullmatch(r"[a-zA-Z0-9_]{3,32}", username))


def email_exists(conn: sqlite3.Connection, email: str) -> bool:
    cur = conn.execute("SELECT 1 FROM users WHERE email = ?;", (email,))
    return cur.fetchone() is not None


def username_exists(conn: sqlite3.Connection, username: str) -> bool:
    cur = conn.execute("SELECT 1 FROM users WHERE username = ?;", (username,))
    return cur.fetchone() is not None


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?;", (email,))
    return cur.fetchone()


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE id = ?;", (user_id,))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?;", (username,))
    return cur.fetchone()


def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str):
    now = datetime.utcnow().isoformat()
    conn.execute(
        "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
        (email, username, password_hash, now)
    )


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str):
    now = datetime.utcnow().isoformat()
    conn.execute(
        """
        INSERT INTO secrets (user_id, secret, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            secret = excluded.secret,
            updated_at = excluded.updated_at;
        """,
        (user_id, secret, now)
    )


def get_secret_for_user(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
    row = cur.fetchone()
    return row["secret"] if row else None


def create_jwt_token(user_id: int, username: str) -> str:
    now = datetime.utcnow()
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": now,
        "exp": now + timedelta(minutes=TOKEN_EXPIRE_MINUTES),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_jwt_token(token: str) -> Dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except (ExpiredSignatureError, InvalidTokenError, jwt.PyJWTError):
        # Will be handled by calling code to return required 401 message
        raise


def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_security)) -> Dict:
    if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        # Unauthorized per schema
        raise jwt.PyJWTError("Invalid authentication token")
    token = credentials.credentials
    payload = decode_jwt_token(token)
    # Validate user exists and matches token claims
    sub = payload.get("sub")
    username_claim = payload.get("username")
    try:
        user_id = int(sub)
    except (TypeError, ValueError):
        raise jwt.PyJWTError("Invalid authentication token")

    conn = get_db_connection()
    try:
        user = get_user_by_id(conn, user_id)
        if not user:
            raise jwt.PyJWTError("Invalid authentication token")
        # Enforce that token's username matches current DB to avoid stale tokens (CWE-863)
        if normalize_username(user["username"]) != normalize_username(username_claim or ""):
            raise jwt.PyJWTError("Invalid authentication token")
        return {"id": user["id"], "email": user["email"], "username": user["username"]}
    finally:
        conn.close()


# Request/Response models (Pydantic)
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class SetSecretRequest(BaseModel):
    username: str
    secret: str


# Routes
@app.on_event("startup")
def on_startup():
    init_db()


@app.post("/register", status_code=201)
def register(payload: RegisterRequest):
    # Validate username format and password requirements
    username_norm = normalize_username(payload.username)
    if not is_valid_username(username_norm) or len(payload.password) < 8 or len(payload.password) > 256:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"}
        )
    password_hash = pbkdf2_sha256.hash(payload.password)

    conn = get_db_connection()
    try:
        # Use combined check to avoid enumeration (CWE-522)
        if email_exists(conn, payload.email) or username_exists(conn, username_norm):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"}
            )
        try:
            create_user(conn, payload.email, username_norm, password_hash)
        except sqlite3.IntegrityError:
            # In case of race condition uniqueness violation
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"}
            )
    finally:
        conn.close()

    return {"message": "Registration successful"}


@app.post("/login")
def login(payload: LoginRequest):
    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, payload.email)
        if not user:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"}
            )
        if not pbkdf2_sha256.verify(payload.password, user["password_hash"]):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"}
            )

        token = create_jwt_token(user["id"], user["username"])
        return {"token": token, "message": "Login successful"}
    finally:
        conn.close()


@app.post("/set_secret")
def set_secret(data: SetSecretRequest, current_user: Dict = Depends(get_current_user)):
    username_norm = normalize_username(data.username)
    if username_norm != normalize_username(current_user["username"]):
        # Enforce resource ownership (CWE-284/CWE-863)
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"}
        )
    conn = get_db_connection()
    try:
        # Ensure target user exists (should be the current user)
        user = get_user_by_username(conn, username_norm)
        if not user or user["id"] != current_user["id"]:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid authentication token"}
            )
        # Store/Update secret using parameterized query (CWE-89)
        upsert_secret(conn, current_user["id"], data.secret)
    finally:
        conn.close()
    return {"message": "Secret has been set successfully"}


@app.get("/get_secret")
def get_secret(username: str, current_user: Dict = Depends(get_current_user)):
    username_norm = normalize_username(username)
    if username_norm != normalize_username(current_user["username"]):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"}
        )
    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, username_norm)
        if not user or user["id"] != current_user["id"]:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid authentication token"}
            )
        secret_val = get_secret_for_user(conn, current_user["id"])
    finally:
        conn.close()
    # If no secret set yet, return empty string to keep response schema simple
    return {"secret": secret_val or ""}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)