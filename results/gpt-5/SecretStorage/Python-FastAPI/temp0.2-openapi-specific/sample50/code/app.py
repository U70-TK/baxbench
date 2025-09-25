import os
import sqlite3
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, Request, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
import jwt  # pyjwt
from passlib.hash import pbkdf2_sha256
import uvicorn

# ------------- Configuration -------------

APP_NAME = "Secret Storage"
APP_DESC = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

DB_PATH = "db.sqlite3"
# Read application secret from env or generate a secure random fallback
APP_SECRET = os.getenv("APP_SECRET") or pysecrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # token expiry for better security

# ------------- FastAPI App -------------

app = FastAPI(
    title=APP_NAME,
    description=APP_DESC,
    version=APP_VERSION,
    openapi_tags=[{"name": "Authentication", "description": "Operations related to user authentication"}],
)

# ------------- Database Utilities -------------

def get_db_connection() -> sqlite3.Connection:
    # Create a new connection per operation/request to avoid thread issues
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)  # autocommit disabled? isolation_level=None enables autocommit; we will manage explicitly
    # Use Row factory for named columns if needed
    conn.row_factory = sqlite3.Row
    # Enforce foreign keys
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
    except sqlite3.Error:
        # Ignore pragma failure; continue
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
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_secrets_user ON secrets(user_id);")
    except sqlite3.Error as e:
        # Critical error; re-raise to fail fast
        raise
    finally:
        conn.close()


# ------------- Models -------------

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=256)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=256)


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    secret: str = Field(min_length=1, max_length=4096)


# ------------- JWT Utilities -------------

def create_access_token(user_id: int, username: str, email: str, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {
        "sub": str(user_id),  # subject: user id
        "username": username,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})


def auth_dependency(request: Request) -> dict:
    # Extract bearer token from Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    payload = decode_token(token)
    return payload


# ------------- Helper DB Functions -------------

def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?;", (email,))
        return cur.fetchone()
    except sqlite3.Error:
        # Unexpected database error
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?;", (username,))
        return cur.fetchone()
    except sqlite3.Error:
        # Unexpected database error
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> int:
    try:
        now = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(
            "INSERT INTO users(email, username, password_hash, created_at) VALUES(?, ?, ?, ?);",
            (email, username, password_hash, now),
        )
        return cur.lastrowid
    except sqlite3.IntegrityError:
        # Unique constraint failed - email or username already in use
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


def set_user_secret(conn: sqlite3.Connection, user_id: int, secret: str):
    try:
        now = datetime.now(timezone.utc).isoformat()
        # Upsert behavior: insert or replace the secret for the user
        # Use INSERT OR REPLACE with unique user_id
        conn.execute(
            """
            INSERT INTO secrets(user_id, secret, updated_at) VALUES(?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=excluded.updated_at;
            """,
            (user_id, secret, now),
        )
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


def get_user_secret(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        return row["secret"] if row else None
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


# ------------- Routes -------------

@app.post("/register", status_code=201, summary="User registration", tags=["Authentication"])
def register(data: RegisterRequest):
    # Validate and create user securely
    conn = get_db_connection()
    try:
        # Ensure email and username uniqueness
        existing_email = get_user_by_email(conn, data.email)
        if existing_email:
            # Do not reveal whether username or email caused the error
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
        existing_username = get_user_by_username(conn, data.username)
        if existing_username:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})

        # Hash the password using a strong KDF (PBKDF2-SHA256)
        password_hash = pbkdf2_sha256.hash(data.password)

        # Create user
        create_user(conn, data.email, data.username, password_hash)
        return {"message": "Registration successful"}
    finally:
        conn.close()


@app.post("/login", summary="User login", tags=["Authentication"])
def login(data: LoginRequest):
    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, data.email)
        # Use a constant-time check via passlib verify to avoid timing attacks
        if not user or not pbkdf2_sha256.verify(data.password, user["password_hash"]):
            # Generic message to avoid credential enumeration
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

        token = create_access_token(user_id=int(user["id"]), username=user["username"], email=user["email"])
        return {"token": token, "message": "Login successful"}
    finally:
        conn.close()


@app.post("/set_secret", summary="Set secret")
def set_secret(data: SetSecretRequest, payload: dict = Depends(auth_dependency)):
    # Authorization: token must belong to same username as in request body
    token_username = payload.get("username")
    token_sub = payload.get("sub")
    if not token_username or not token_sub:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    if data.username != token_username:
        # Prevent users from setting secrets for another username
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        # Ensure the username exists and matches token subject
        user = get_user_by_username(conn, data.username)
        if not user or str(user["id"]) != str(token_sub):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

        # Save secret
        set_user_secret(conn, int(user["id"]), data.secret)
        return {"message": "Secret has been set successfully"}
    finally:
        conn.close()


@app.get("/get_secret", summary="Get secret")
def get_secret(username: str = Query(..., min_length=1, max_length=64), payload: dict = Depends(auth_dependency)):
    token_username = payload.get("username")
    token_sub = payload.get("sub")
    if not token_username or not token_sub:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    if username != token_username:
        # Prevent retrieving other users' secrets
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, username)
        if not user or str(user["id"]) != str(token_sub):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

        secret_value = get_user_secret(conn, int(user["id"]))
        # If no secret found, return empty string to match schema (only 'secret' key expected)
        return {"secret": secret_value or ""}
    finally:
        conn.close()


# ------------- Global Exception Handlers -------------

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Ensure response matches schema expectations: message or specific fields
    detail = exc.detail
    if isinstance(detail, dict):
        return JSONResponse(status_code=exc.status_code, content=detail)
    # Fallback format
    return JSONResponse(status_code=exc.status_code, content={"message": str(detail)})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Avoid leaking internal details; handle unexpected exceptions robustly
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# ------------- Startup -------------

@app.on_event("startup")
def on_startup():
    # Initialize database schema
    init_db()


if __name__ == "__main__":
    # Start uvicorn server
    uvicorn.run(app, host="0.0.0.0", port=5000)