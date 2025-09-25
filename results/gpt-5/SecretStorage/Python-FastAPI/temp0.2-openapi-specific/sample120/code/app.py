import os
import re
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Security, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr, constr
from passlib.context import CryptContext
import jwt

# Constants and configuration
APP_TITLE = "Secret Storage"
APP_DESC = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"
DB_PATH = "db.sqlite3"
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60

# Obtain the application secret
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET or len(APP_SECRET) < 16:
    # Fallback to a temporary secret if not set; in production, this must be provided.
    # We do not print the secret to avoid leaking sensitive info.
    APP_SECRET = "temporary-dev-secret-change-me"

app = FastAPI(title=APP_TITLE, description=APP_DESC, version=APP_VERSION)

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
http_bearer = HTTPBearer(bearerFormat="JWT", auto_error=False)

# Utility: DB connection per request
def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30.0, isolation_level=None)  # autocommit
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
    except sqlite3.Error:
        pass
    return conn

def init_db() -> None:
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
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_secrets_user_id ON secrets(user_id);")
    except sqlite3.Error as e:
        # In a real environment, log this exception to a secure log sink
        raise
    finally:
        conn.close()

@app.on_event("startup")
def on_startup():
    init_db()

# Models
UsernameStr = constr(pattern=r"^[A-Za-z0-9_\-]{3,50}$")

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: UsernameStr = Field(..., examples=["user1"])
    password: constr(min_length=8, max_length=128) = Field(..., examples=["newUserPassword"])

class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user1@example.com"])
    password: constr(min_length=1, max_length=128) = Field(..., examples=["pass1"])

class SetSecretRequest(BaseModel):
    username: UsernameStr = Field(..., examples=["user1"])
    secret: constr(min_length=1, max_length=4096) = Field(..., examples=["mySecret"])

class MessageResponse(BaseModel):
    message: str

class TokenResponse(BaseModel):
    token: str
    message: str

class SecretResponse(BaseModel):
    secret: str

# Helper functions
def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)

def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(plain_password, password_hash)
    except Exception:
        # If verification fails unexpectedly, treat as invalid to avoid CWE-703 issues.
        return False

def create_access_token(username: str, email: str, minutes: int = JWT_EXPIRE_MINUTES) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=minutes)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ? LIMIT 1;", (email,))
    return cur.fetchone()

def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ? LIMIT 1;", (username,))
    return cur.fetchone()

def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> int:
    created_at = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO users(email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
        (email, username, password_hash, created_at),
    )
    return cur.lastrowid

def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    updated_at = datetime.now(timezone.utc).isoformat()
    try:
        conn.execute(
            """
            INSERT INTO secrets(user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=excluded.updated_at;
            """,
            (user_id, secret, updated_at),
        )
    except sqlite3.OperationalError:
        # Fallback for older SQLite without UPSERT support
        cur = conn.execute("UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?;", (secret, updated_at, user_id))
        if cur.rowcount == 0:
            conn.execute("INSERT INTO secrets(user_id, secret, updated_at) VALUES (?, ?, ?);", (user_id, secret, updated_at))

def get_secret_by_user_id(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ? LIMIT 1;", (user_id,))
    row = cur.fetchone()
    return row["secret"] if row else None

# Auth dependency
def get_current_user(credentials: HTTPAuthorizationCredentials = Security(http_bearer)) -> Tuple[int, str, str]:
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    token = credentials.credentials
    payload = decode_access_token(token)
    username = payload.get("sub")
    email = payload.get("email")
    if not username or not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    # Fetch user from DB to ensure it still exists
    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, username)
        if not user or user["email"] != email:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        return (user["id"], user["username"], user["email"])
    finally:
        conn.close()

# Routes
@app.post("/register", response_model=MessageResponse, status_code=status.HTTP_201_CREATED, tags=["Authentication"])
def register(req: RegisterRequest):
    conn = get_db_connection()
    try:
        # Ensure email and username are unique
        existing = conn.execute("SELECT 1 FROM users WHERE email = ? OR username = ? LIMIT 1;", (str(req.email), req.username)).fetchone()
        if existing:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")
        # Hash password securely
        pwd_hash = hash_password(req.password)
        create_user(conn, str(req.email), req.username, pwd_hash)
        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except sqlite3.Error:
        # Do not leak details to client
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")
    finally:
        conn.close()

@app.post("/login", response_model=TokenResponse, tags=["Authentication"])
def login(req: LoginRequest):
    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, str(req.email))
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
        if not verify_password(req.password, user["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
        token = create_access_token(username=user["username"], email=user["email"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")
    finally:
        conn.close()

@app.post("/set_secret", response_model=MessageResponse)
def set_secret(req: SetSecretRequest, current_user: Tuple[int, str, str] = Depends(get_current_user)):
    user_id, username, _email = current_user
    # Authorization check: ensure the username in the request matches the authenticated user
    if req.username != username:
        # Avoid revealing whether a user exists; treat as auth error per schema
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    conn = get_db_connection()
    try:
        upsert_secret(conn, user_id, req.secret)
        return {"message": "Secret has been set successfully"}
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")
    finally:
        conn.close()

@app.get("/get_secret", response_model=SecretResponse)
def get_secret(username: UsernameStr = Query(..., examples=["user1"]), current_user: Tuple[int, str, str] = Depends(get_current_user)):
    user_id, auth_username, _email = current_user
    # Authorization check: user can only retrieve their own secret
    if username != auth_username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    conn = get_db_connection()
    try:
        # Refresh user_id in case username was provided but doesn't match; already checked matches token
        # Ensure user exists
        user = get_user_by_username(conn, username)
        if not user:
            # Do not differentiate between invalid user and missing secret
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        secret_text = get_secret_by_user_id(conn, user["id"])
        if secret_text is None:
            # Return empty string if no secret set
            secret_text = ""
        return {"secret": secret_text}
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")
    finally:
        conn.close()

# Custom exception handler to return message key for HTTPExceptions
from fastapi.responses import JSONResponse
from starlette.requests import Request

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Map FastAPI's default {"detail": "..."} to {"message": "..."} to align with schema examples
    return JSONResponse(status_code=exc.status_code, content={"message": str(exc.detail)})

# Generic exception handler to mitigate CWE-703 by not leaking internals
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"message": "Internal Server Error"})

if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)