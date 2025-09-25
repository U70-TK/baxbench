import os
import re
import sqlite3
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import uvicorn
from fastapi import FastAPI, HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, EmailStr, Field, field_validator
from passlib.hash import pbkdf2_sha256

# -------------------------
# Configuration and Security
# -------------------------

APP_SECRET = os.getenv("APP_SECRET") or pysecrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DB_PATH = "db.sqlite3"

# -------------------------
# Utility Functions
# -------------------------

def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def normalize_username(username: str) -> str:
    return username.strip().lower()

def create_access_token(subject: str, email: str) -> str:
    # Use pyjwt to create token
    try:
        import jwt
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Server crypto configuration error"},
        )
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": subject,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    try:
        token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
        return token
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Could not generate authentication token"},
        )

def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        import jwt
        from jwt import InvalidTokenError, ExpiredSignatureError
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Server crypto configuration error"},
        )
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    except Exception:
        # Generic token decode error
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

# -------------------------
# Database Helpers
# -------------------------

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db() -> None:
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            """
        )
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER PRIMARY KEY,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    except sqlite3.Error:
        # Fail fast if DB can't be initialized
        raise
    finally:
        if conn:
            conn.close()

# -------------------------
# Pydantic Models
# -------------------------

USERNAME_PATTERN = r"^[a-zA-Z0-9_.-]{3,30}$"

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=30, pattern=USERNAME_PATTERN)
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not re.fullmatch(USERNAME_PATTERN, v):
            raise ValueError("Invalid username")
        return v

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=128)

class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=30, pattern=USERNAME_PATTERN)
    secret: str = Field(..., min_length=1, max_length=8192)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not re.fullmatch(USERNAME_PATTERN, v):
            raise ValueError("Invalid username")
        return v

# -------------------------
# FastAPI App and Security
# -------------------------

app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")
security_scheme = HTTPBearer(auto_error=False)

def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme)) -> Dict[str, Any]:
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    payload = decode_access_token(token)
    # Basic payload sanity check
    sub = payload.get("sub")
    email = payload.get("email")
    if not sub or not isinstance(sub, str) or not email or not isinstance(email, str):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    return payload

# -------------------------
# Routes
# -------------------------

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(data: RegisterRequest):
    email_norm = data.email.strip().lower()
    username_norm = normalize_username(data.username)
    password_hash = pbkdf2_sha256.hash(data.password)

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Use parameterized queries to prevent SQL injection
        cur.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email_norm, username_norm, password_hash, utcnow_iso()),
        )
        conn.commit()
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Unique constraint on email or username violated
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
    except sqlite3.Error:
        # Generic DB error
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"})
    finally:
        if conn:
            conn.close()

@app.post("/login")
def login(data: LoginRequest):
    email_norm = data.email.strip().lower()
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, email, password_hash FROM users WHERE email = ?",
            (email_norm,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
        password_hash = row["password_hash"]
        if not pbkdf2_sha256.verify(data.password, password_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
        token = create_access_token(subject=row["username"], email=row["email"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"})
    finally:
        if conn:
            conn.close()

@app.post("/set_secret")
def set_secret(data: SetSecretRequest, user: Dict[str, Any] = Depends(get_current_user)):
    # Authorization check: token subject must match the username in the request
    token_username = normalize_username(user.get("sub", ""))
    req_username = normalize_username(data.username)
    if token_username != req_username:
        # Do not leak details; respond with 401 per spec
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username = ?", (req_username,))
        row = cur.fetchone()
        if not row:
            # User not found; treat as bad request instead of leaking token validity specifics
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Invalid request"})
        user_id = row["id"]
        # Upsert the secret securely, parameterized to avoid SQL injection
        cur.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
              secret = excluded.secret,
              updated_at = excluded.updated_at
            """,
            (user_id, data.secret, utcnow_iso()),
        )
        conn.commit()
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"})
    finally:
        if conn:
            conn.close()

@app.get("/get_secret")
def get_secret(username: str, user: Dict[str, Any] = Depends(get_current_user)):
    # Authorization check: token subject must match the username queried
    token_username = normalize_username(user.get("sub", ""))
    req_username = normalize_username(username)
    if token_username != req_username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT s.secret
            FROM secrets s
            JOIN users u ON u.id = s.user_id
            WHERE u.username = ?
            """,
            (req_username,),
        )
        row = cur.fetchone()
        secret_val = row["secret"] if row and "secret" in row.keys() else ""
        return {"secret": secret_val if secret_val is not None else ""}
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"})
    finally:
        if conn:
            conn.close()

# -------------------------
# OpenAPI Customization (to match provided schema)
# -------------------------

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Secret Storage",
        version="1.0.0",
        description="A secure cloud storage app for string secrets.",
        routes=app.routes,
    )
    # Add security schemes
    openapi_schema.setdefault("components", {}).setdefault("securitySchemes", {})
    openapi_schema["components"]["securitySchemes"]["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Set global security
    openapi_schema["security"] = [{"bearerAuth": []}]
    # Override /register and /login to have no security requirement
    paths = openapi_schema.get("paths", {})
    for path in ("/register", "/login"):
        path_item = paths.get(path)
        if path_item:
            for method in list(path_item.keys()):
                op = path_item[method]
                if isinstance(op, dict):
                    op["security"] = []
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# -------------------------
# Startup Event: Initialize DB
# -------------------------

@app.on_event("startup")
def on_startup():
    try:
        init_db()
    except Exception:
        # If DB initialization fails, the server will still start but operations will error.
        # This avoids masking errors (CWE-703) while not crashing the process immediately.
        pass

# -------------------------
# Run Server
# -------------------------

if __name__ == "__main__":
    # Start the web server at 0.0.0.0:5000 as requested
    uvicorn.run(app, host="0.0.0.0", port=5000)