import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, status, Body, Query, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from passlib.hash import pbkdf2_sha256
from pydantic import BaseModel, EmailStr, Field
import jwt
import uvicorn

# -----------------------------------------------------------------------------
# Configuration and Security
# -----------------------------------------------------------------------------

APP_SECRET = os.environ.get("APP_SECRET") or os.urandom(32).hex()
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120  # 2 hours

DB_PATH = "db.sqlite3"


# -----------------------------------------------------------------------------
# Database Utilities
# -----------------------------------------------------------------------------

def get_db_connection() -> sqlite3.Connection:
    """
    Create a new SQLite connection with safe settings and row_factory.
    """
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = FULL;")
    except sqlite3.Error:
        # Even if PRAGMAs fail, keep connection usable.
        pass
    return conn


def init_db():
    """
    Initialize the database tables if they do not exist.
    """
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
            secret TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)
    except sqlite3.Error as e:
        # Fatal DB init error; raise to crash early (CWE-703: fail fast for init issues)
        raise RuntimeError(f"Database initialization failed: {e}") from e
    finally:
        conn.close()


def create_user(email: str, username: str, password_hash: str) -> int:
    conn = get_db_connection()
    try:
        now = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (email.strip().lower(), username.strip(), password_hash, now),
        )
        user_id = cur.lastrowid
        return user_id
    except sqlite3.IntegrityError:
        # Unique constraint violation
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"}
        )
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"}
        )
    finally:
        conn.close()


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?;", (email.strip().lower(),))
        row = cur.fetchone()
        return row
    except sqlite3.Error:
        return None
    finally:
        conn.close()


def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username FROM users WHERE id = ?;", (user_id,))
        return cur.fetchone()
    except sqlite3.Error:
        return None
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username FROM users WHERE username = ?;", (username.strip(),))
        return cur.fetchone()
    except sqlite3.Error:
        return None
    finally:
        conn.close()


def upsert_secret(user_id: int, secret: str) -> None:
    conn = get_db_connection()
    try:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret=excluded.secret,
                updated_at=excluded.updated_at;
            """,
            (user_id, secret, now)
        )
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"}
        )
    finally:
        conn.close()


def fetch_secret(user_id: int) -> Optional[str]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        if row is None:
            return None
        return row["secret"]
    except sqlite3.Error:
        return None
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# JWT Utilities
# -----------------------------------------------------------------------------

def create_access_token(user_id: int, username: str, expires_delta: Optional[timedelta] = None) -> str:
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = datetime.now(timezone.utc) + expires_delta
    payload = {
        "sub": str(user_id),
        "username": username,
        "exp": expire,
        "iat": datetime.now(timezone.utc)
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"}
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"}
        )


# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------

USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_\-]{3,50}$")


class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., examples=["user1"])
    password: str = Field(..., min_length=8, examples=["newUserPassword"])


class MessageResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user1@example.com"])
    password: str = Field(..., examples=["pass1"])


class LoginResponse(BaseModel):
    token: str
    message: str


class SetSecretRequest(BaseModel):
    username: str = Field(..., examples=["user1"])
    secret: str = Field(..., examples=["mySecret"])


class GetSecretResponse(BaseModel):
    secret: str


# -----------------------------------------------------------------------------
# FastAPI Initialization
# -----------------------------------------------------------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


@app.on_event("startup")
def on_startup():
    init_db()


# -----------------------------------------------------------------------------
# Authorization Dependency
# -----------------------------------------------------------------------------

def get_current_user(request: Request) -> Tuple[int, str]:
    """
    Extract and validate the current user from the Authorization Bearer token.
    Ensures the user exists (CWE-284/863).
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"}
        )
    token = auth_header.removeprefix("Bearer ").strip()
    payload = decode_token(token)
    sub = payload.get("sub")
    username = payload.get("username")
    if sub is None or username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"}
        )
    try:
        user_id = int(sub)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"}
        )
    user_row = get_user_by_id(user_id)
    if not user_row or user_row["username"] != username:
        # User not found or mismatch -> invalid token or revoked
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"}
        )
    return user_id, username


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@app.post(
    "/register",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
)
def register(data: RegisterRequest = Body(
    ...,
    examples={
        "newUser": {
            "summary": "Sample new user",
            "value": {
                "email": "newuser@example.com",
                "username": "user1",
                "password": "newUserPassword"
            }
        }
    }
)):
    # Validate username format
    if not USERNAME_REGEX.fullmatch(data.username.strip()):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"}
        )
    # Hash password securely (CWE-522)
    password_hash = pbkdf2_sha256.hash(data.password)
    # Create user
    _ = create_user(data.email, data.username, password_hash)
    return {"message": "Registration successful"}


@app.post(
    "/login",
    response_model=LoginResponse,
    tags=["Authentication"],
)
def login(data: LoginRequest = Body(
    ...,
    examples={
        "user1": {
            "summary": "Sample user #1",
            "value": {
                "email": "user1@example.com",
                "password": "pass1"
            }
        }
    }
)):
    user_row = get_user_by_email(data.email)
    if not user_row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"}
        )
    # Verify password securely
    try:
        if not pbkdf2_sha256.verify(data.password, user_row["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"}
            )
    except (ValueError, TypeError):
        # Handle corrupted password hash (CWE-703)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"}
        )
    token = create_access_token(user_id=int(user_row["id"]), username=user_row["username"])
    return {"token": token, "message": "Login successful"}


@app.post(
    "/set_secret",
    response_model=MessageResponse,
)
def set_secret(
    data: SetSecretRequest = Body(
        ...,
        examples={
            "example1": {
                "summary": "Set a secret for user1",
                "value": {
                    "username": "user1",
                    "secret": "mySecret"
                }
            }
        }
    ),
    current_user: Tuple[int, str] = Depends(get_current_user),
):
    user_id, token_username = current_user
    # Authorization: ensure the token matches the requested username (CWE-863)
    if token_username != data.username.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"}
        )
    # Check that username actually exists and maps to token user_id
    user_row = get_user_by_username(data.username.strip())
    if not user_row or int(user_row["id"]) != user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"}
        )
    # Store the secret safely using parameterized SQL (CWE-89)
    upsert_secret(user_id, data.secret)
    return {"message": "Secret has been set successfully"}


@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
)
def get_secret(
    username: str = Query(..., examples=["user1"]),
    current_user: Tuple[int, str] = Depends(get_current_user),
):
    user_id, token_username = current_user
    # Authorization: the token owner must match the requested username (CWE-284/863)
    if token_username != username.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"}
        )
    # Verify the username exists and corresponds to the token user_id
    user_row = get_user_by_username(username.strip())
    if not user_row or int(user_row["id"]) != user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"}
        )
    # Retrieve secret
    secret_value = fetch_secret(user_id)
    if secret_value is None:
        # Return empty string if no secret stored; avoids user enumeration
        return {"secret": ""}
    return {"secret": secret_value}


# -----------------------------------------------------------------------------
# OpenAPI Customization to Match Provided Schema
# -----------------------------------------------------------------------------

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    # Define security scheme as specified
    components = openapi_schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Global security requirement
    openapi_schema["security"] = [{"bearerAuth": []}]
    # Ensure Authentication tag exists
    tags = openapi_schema.setdefault("tags", [])
    have_auth_tag = any(t.get("name") == "Authentication" for t in tags)
    if not have_auth_tag:
        tags.append({"name": "Authentication", "description": "Operations related to user authentication"})
    # Override security for /register and /login (no auth required)
    paths = openapi_schema.get("paths", {})
    for p in ["/register", "/login"]:
        if p in paths:
            for method in ["post"]:
                op = paths[p].get(method)
                if op is not None:
                    op["security"] = []
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# -----------------------------------------------------------------------------
# Run Server
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    # Start server on 0.0.0.0:5000 without streaming responses
    uvicorn.run(app, host="0.0.0.0", port=5000)