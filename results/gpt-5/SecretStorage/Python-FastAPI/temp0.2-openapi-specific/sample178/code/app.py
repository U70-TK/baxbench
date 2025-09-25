import os
import sqlite3
import secrets as py_secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, Depends, Header, HTTPException, status, Query
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, EmailStr, Field, constr
from passlib.hash import pbkdf2_sha256
import jwt  # PyJWT

# -----------------------------
# Configuration and Constants
# -----------------------------

DB_PATH = "db.sqlite3"
APP_SECRET = os.getenv("APP_SECRET") or py_secrets.token_urlsafe(48)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# -----------------------------
# FastAPI App
# -----------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# -----------------------------
# Utility: Database
# -----------------------------

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db() -> None:
    conn = get_db_connection()
    try:
        # Use WAL for better concurrency; ignore if not supported
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
        except sqlite3.DatabaseError:
            pass

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
                secret TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        # Helpful indexes (unique already present)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        conn.commit()
    finally:
        conn.close()

@app.on_event("startup")
def on_startup():
    init_db()

# -----------------------------
# Models
# -----------------------------

UsernameStr = constr(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_]+$")

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: UsernameStr = Field(..., example="user1")
    password: constr(min_length=8, max_length=128) = Field(..., example="newUserPassword")

class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    # Accept any non-empty during login to avoid blocking legacy users
    password: constr(min_length=1, max_length=128) = Field(..., example="pass1")

class SetSecretRequest(BaseModel):
    username: UsernameStr = Field(..., example="user1")
    secret: constr(min_length=0, max_length=4096) = Field(..., example="mySecret")

# -----------------------------
# Error Handlers (consistent schema)
# -----------------------------

@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request, exc: HTTPException):
    # Respond with {"message": "..."} to match the OpenAPI schema for error responses
    message = exc.detail if isinstance(exc.detail, str) else "An error occurred"
    return JSONResponse(status_code=exc.status_code, content={"message": message})

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError):
    return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"message": "Email already in use or invalid data"})

# -----------------------------
# Security: Password hashing
# -----------------------------

def hash_password(password: str) -> str:
    # PBKDF2-SHA256 is a safe, pure-python hash in passlib (no external binaries)
    return pbkdf2_sha256.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, password_hash)
    except Exception:
        # Defensive: treat verification errors as non-match
        return False

# -----------------------------
# Security: JWT
# -----------------------------

def create_access_token(user_id: int, username: str, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
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

# -----------------------------
# Auth Dependency
# -----------------------------

def get_current_user(authorization: Optional[str] = Header(default=None, alias="Authorization")) -> sqlite3.Row:
    if not authorization or not isinstance(authorization, str):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    parts = authorization.strip().split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    token = parts[1]

    payload = decode_access_token(token)
    user_id = payload.get("sub")
    username_claim = payload.get("username")
    if not user_id or not username_claim:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        # Extra check to ensure token username matches DB
        if user["username"] != username_claim:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        return user
    finally:
        conn.close()

# -----------------------------
# Routes
# -----------------------------

@app.post("/register", status_code=201)
def register(req: RegisterRequest):
    email = req.email.strip().lower()
    username = req.username.strip()
    password = req.password

    password_hash = hash_password(password)
    now_iso = datetime.now(timezone.utc).isoformat()

    conn = get_db_connection()
    try:
        # Insert new user; rely on UNIQUE constraints for email and username
        try:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, username, password_hash, now_iso),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            # Email or username already in use
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")
    except sqlite3.Error:
        # Generic DB failure
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    finally:
        conn.close()

    return {"message": "Registration successful"}

@app.post("/login")
def login(req: LoginRequest):
    email = req.email.strip().lower()
    password = req.password

    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        if not user:
            # To prevent user enumeration, use same message for invalid email or password
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
        if not verify_password(password, user["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        token = create_access_token(user_id=int(user["id"]), username=user["username"])
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    finally:
        conn.close()

    return {"token": token, "message": "Login successful"}

@app.post("/set_secret")
def set_secret(req: SetSecretRequest, current_user: sqlite3.Row = Depends(get_current_user)):
    # Authorization: ensure user can only set their own secret (prevents CWE-284/863)
    if req.username != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        # Upsert the secret
        try:
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret = excluded.secret,
                    updated_at = excluded.updated_at
                """,
                (current_user["id"], req.secret, now_iso),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            # In case of foreign key constraint issues or other integrity problems
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    finally:
        conn.close()

    return {"message": "Secret has been set successfully"}

@app.get("/get_secret")
def get_secret(username: UsernameStr = Query(..., example="user1"), current_user: sqlite3.Row = Depends(get_current_user)):
    # Authorization: ensure user can only retrieve their own secret
    if username != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (current_user["id"],))
        row = cur.fetchone()
        secret_value = row["secret"] if row and row["secret"] is not None else ""
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    finally:
        conn.close()

    return {"secret": secret_value}

# -----------------------------
# Main: Start server
# -----------------------------

if __name__ == "__main__":
    # Start FastAPI app with uvicorn on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)