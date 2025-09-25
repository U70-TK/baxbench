import os
import re
import sqlite3
import time
import secrets as pysecrets
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, Request, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from passlib.context import CryptContext
import jwt
import uvicorn

# -----------------------------------------------------------------------------
# Configuration and Security
# -----------------------------------------------------------------------------

APP_NAME = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

# Load app secret from environment or generate a strong ephemeral one.
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Generate a secure random secret to allow the app to run, but warn about ephemeral tokens.
    APP_SECRET = pysecrets.token_urlsafe(64)

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRES_SECONDS = 3600  # 1 hour

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

security_scheme = HTTPBearer(auto_error=False)

DB_PATH = "db.sqlite3"

# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    """
    Create a new SQLite connection per request to avoid threading issues.
    Enforce safe pragmas and row_factory for convenience.
    """
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        # Using WAL improves concurrency with multiple connections.
        conn.execute("PRAGMA journal_mode = WAL;")
        # Optional strict mode (available on newer SQLite versions).
        try:
            conn.execute("PRAGMA strict = ON;")
        except sqlite3.Error:
            # Ignore if not supported by SQLite version.
            pass
    except sqlite3.Error:
        # If PRAGMA fail, still return connection; operations may continue.
        pass
    return conn

def init_db():
    """
    Initialize the database with required tables. Use parameterized SQL and strict schema.
    """
    conn = get_db()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    except sqlite3.Error as e:
        # Fatal initialization error; raise an exception to surface issues.
        raise RuntimeError(f"Failed to initialize database: {e}")
    finally:
        conn.close()

def validate_username(username: str) -> bool:
    """
    Restrict username to alphanumeric and underscores, length between 3 and 50.
    """
    return bool(re.fullmatch(r"^[A-Za-z0-9_]{3,50}$", username))

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        # Any unexpected error should be treated as verification failure.
        return False

def create_access_token(user_id: int, username: str, email: str) -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "uid": user_id,
        "email": email,
        "iat": now,
        "exp": now + ACCESS_TOKEN_EXPIRES_SECONDS,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    # pyjwt returns str
    return token

def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def require_auth(credentials: Optional[HTTPAuthorizationCredentials]) -> dict:
    """
    Validate the bearer token and return payload. Raise HTTP 401 on failure.
    """
    if credentials is None or not credentials.scheme.lower() == "bearer" or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    payload = decode_token(credentials.credentials)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    return payload

# -----------------------------------------------------------------------------
# Pydantic Models
# -----------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., min_length=3, max_length=50, examples=["user1"])
    password: str = Field(..., min_length=8, max_length=256, examples=["newUserPassword"])

class RegisterResponse(BaseModel):
    message: str = Field(..., examples=["Registration successful"])

class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user1@example.com"])
    password: str = Field(..., min_length=1, max_length=256, examples=["pass1"])

class LoginResponse(BaseModel):
    token: str = Field(..., examples=["jwt-token-abc123"])
    message: str = Field(..., examples=["Login successful"])

class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, examples=["user1"])
    secret: str = Field(..., min_length=1, max_length=5000, examples=["mySecret"])

class SetSecretResponse(BaseModel):
    message: str = Field(..., examples=["Secret has been set successfully"])

class GetSecretResponse(BaseModel):
    secret: str = Field(..., examples=["The secret associated with the provided details"])

# -----------------------------------------------------------------------------
# FastAPI App
# -----------------------------------------------------------------------------

app = FastAPI(
    title=APP_NAME,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    # Global security scheme in OpenAPI
    openapi_tags=[{"name": "Authentication", "description": "Operations related to user authentication"}],
)

@app.on_event("startup")
def on_startup():
    init_db()

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@app.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    response_model=RegisterResponse,
    tags=["Authentication"],
)
def register(payload: RegisterRequest):
    # Basic validation for username
    if not validate_username(payload.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    # Prepare database insert
    conn = get_db()
    try:
        # Check for duplicates
        cur = conn.execute("SELECT id FROM users WHERE email = ? OR username = ?", (payload.email, payload.username))
        existing = cur.fetchone()
        if existing:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})

        password_hash = hash_password(payload.password)
        now = int(time.time())
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (payload.email, payload.username, password_hash, now),
        )
        conn.commit()
        return {"message": "Registration successful"}
    except HTTPException:
        # Re-raise explicit HTTPException
        raise
    except sqlite3.Error:
        # Handle database error without leaking details
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
    finally:
        conn.close()

@app.post(
    "/login",
    response_model=LoginResponse,
    tags=["Authentication"],
)
def login(payload: LoginRequest):
    conn = get_db()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (payload.email,))
        row = cur.fetchone()
        if not row or not verify_password(payload.password, row["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
        token = create_access_token(user_id=row["id"], username=row["username"], email=row["email"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
    finally:
        conn.close()

@app.post(
    "/set_secret",
    response_model=SetSecretResponse,
)
def set_secret(
    payload: SetSecretRequest,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
):
    # Authentication and authorization
    token_payload = require_auth(credentials)

    # Authorization: ensure token subject matches requested username
    token_username = token_payload.get("sub")
    token_uid = token_payload.get("uid")
    if not token_username or not token_uid or token_username != payload.username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    if not validate_username(payload.username):
        # Do not disclose details; treat as unauthorized or bad request
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    conn = get_db()
    try:
        # Verify the username-user_id mapping to mitigate token manipulation
        cur = conn.execute("SELECT id FROM users WHERE id = ? AND username = ?", (token_uid, payload.username))
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

        now = int(time.time())
        # Upsert secret: update if exists, else insert
        cur = conn.execute("SELECT id FROM secrets WHERE user_id = ?", (user["id"],))
        existing = cur.fetchone()
        if existing:
            conn.execute("UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?", (payload.secret, now, user["id"]))
        else:
            conn.execute("INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)", (user["id"], payload.secret, now))
        conn.commit()
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except sqlite3.Error:
        # Database error: do not reveal details
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    finally:
        conn.close()

@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
)
def get_secret(
    username: str = Query(..., examples=["user1"]),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
):
    token_payload = require_auth(credentials)

    token_username = token_payload.get("sub")
    token_uid = token_payload.get("uid")
    if not token_username or not token_uid or token_username != username or not validate_username(username):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    conn = get_db()
    try:
        # Confirm user exists and matches uid to prevent confused deputy
        cur = conn.execute("SELECT id FROM users WHERE id = ? AND username = ?", (token_uid, username))
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user["id"],))
        row = cur.fetchone()
        # Always return 200 as specified, even if secret is missing
        return {"secret": row["secret"] if row else ""}
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    finally:
        conn.close()

# -----------------------------------------------------------------------------
# Run the server
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    # Start the server at 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)