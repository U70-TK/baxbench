import os
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Body, Query, Request
from fastapi.openapi.utils import get_openapi
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, constr
from passlib.context import CryptContext
import jwt

# ---------------------------
# Configuration and Security
# ---------------------------

APP_NAME = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"
DB_PATH = "db.sqlite3"

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(APP_NAME)

# Load or generate application secret
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fall back to a runtime-only secret if env var is missing.
    # Tokens will be invalidated on restart. In production, always set APP_SECRET.
    import secrets as _secrets

    APP_SECRET = _secrets.token_urlsafe(64)
    logger.warning("APP_SECRET environment variable not set. Using a temporary secret for this process only.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Password hashing (no external dependencies required by using pbkdf2_sha256)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# HTTP Bearer security scheme
bearer_scheme = HTTPBearer(auto_error=False)

# ---------------------------
# Database Utilities
# ---------------------------

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    # Ensure FK support
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    try:
        conn = get_db_connection()
        try:
            # Set WAL for better concurrency and durability
            conn.execute("PRAGMA journal_mode = WAL;")
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
                    secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            """
            )
        finally:
            conn.close()
    except sqlite3.Error as e:
        logger.exception("Failed to initialize database: %s", e)
        raise

# ---------------------------
# Pydantic Models
# ---------------------------

UsernameStr = constr(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")

class RegisterRequest(BaseModel):
    email: EmailStr
    username: UsernameStr
    password: constr(min_length=8, max_length=128)

class LoginRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=1, max_length=128)

class SetSecretRequest(BaseModel):
    username: UsernameStr
    secret: constr(min_length=1, max_length=8192)

class TokenResponse(BaseModel):
    token: str
    message: str

class MessageResponse(BaseModel):
    message: str

class SecretResponse(BaseModel):
    secret: str

# ---------------------------
# Security Helpers
# ---------------------------

def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(plain_password, password_hash)
    except Exception:
        return False

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(*, user_id: int, username: str, email: str, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(tz=timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode = {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "iss": APP_NAME,
    }
    token = jwt.encode(to_encode, APP_SECRET, algorithm=ALGORITHM)
    return token

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM], options={"require": ["exp", "sub"]})
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

# Dependency to get current user from header token
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    payload = decode_token(token)
    # Basic shape validation
    if "sub" not in payload or "username" not in payload:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    return payload

# ---------------------------
# Data Access Helpers
# ---------------------------

def db_get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?", (email,))
        return cur.fetchone()
    except sqlite3.Error as e:
        logger.exception("Database error on db_get_user_by_email: %s", e)
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})
    finally:
        conn.close()

def db_get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?", (username,))
        return cur.fetchone()
    except sqlite3.Error as e:
        logger.exception("Database error on db_get_user_by_username: %s", e)
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})
    finally:
        conn.close()

def db_create_user(email: str, username: str, password_hash: str) -> int:
    conn = get_db_connection()
    try:
        now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        cur = conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, now),
        )
        return cur.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
    except sqlite3.Error as e:
        logger.exception("Database error on db_create_user: %s", e)
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})
    finally:
        conn.close()

def db_upsert_secret(user_id: int, secret: str) -> None:
    conn = get_db_connection()
    try:
        now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        # Use INSERT OR REPLACE to upsert while keeping PK
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=excluded.updated_at
            """,
            (user_id, secret, now),
        )
    except sqlite3.Error as e:
        logger.exception("Database error on db_upsert_secret: %s", e)
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})
    finally:
        conn.close()

def db_get_secret(user_id: int) -> Optional[str]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        return row["secret"] if row else None
    except sqlite3.Error as e:
        logger.exception("Database error on db_get_secret: %s", e)
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})
    finally:
        conn.close()

# ---------------------------
# FastAPI App
# ---------------------------

app = FastAPI(
    title=APP_NAME,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

@app.on_event("startup")
def on_startup():
    init_db()

# ---------------------------
# Routes
# ---------------------------

@app.post(
    "/register",
    summary="User registration",
    description="Register a new user with email, username and password.",
    response_model=MessageResponse,
    status_code=201,
)
def register(payload: RegisterRequest = Body(..., examples={
    "newUser": {
        "summary": "Sample new user",
        "value": {"email": "newuser@example.com", "username": "user1", "password": "newUserPassword"},
    }
})):
    email = payload.email.strip()
    username = payload.username.strip()
    password = payload.password

    # Defensive checks to prevent trivial issues
    if not email or not username or not password:
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

    # Ensure email uniqueness and username uniqueness
    existing_by_email = db_get_user_by_email(email)
    if existing_by_email:
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
    existing_by_username = db_get_user_by_username(username)
    if existing_by_username:
        # The spec focuses on email message, but we return same generic to avoid user enumeration
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

    password_hash = hash_password(password)
    db_create_user(email, username, password_hash)
    return {"message": "Registration successful"}

@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
    response_model=TokenResponse,
)
def login(payload: LoginRequest = Body(..., examples={
    "user1": {
        "summary": "Sample user #1",
        "value": {"email": "user1@example.com", "password": "pass1"},
    }
})):
    email = payload.email.strip()
    password = payload.password

    user = db_get_user_by_email(email)
    if not user:
        # Generic message to prevent user enumeration
        raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})

    if not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})

    token = create_access_token(user_id=user["id"], username=user["username"], email=user["email"])
    return {"token": token, "message": "Login successful"}

@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
    response_model=MessageResponse,
)
def set_secret(
    payload: SetSecretRequest = Body(
        ..., examples={"example1": {"summary": "Set a secret for user1", "value": {"username": "user1", "secret": "mySecret"}}}
    ),
    current_user: dict = Depends(get_current_user),
):
    token_username = current_user.get("username")
    if token_username != payload.username:
        # Authorization check to ensure user can only set their own secret
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    user = db_get_user_by_username(payload.username)
    if not user:
        # If token was valid but user not found, treat as invalid token
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    db_upsert_secret(user_id=user["id"], secret=payload.secret)
    return {"message": "Secret has been set successfully"}

@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
    response_model=SecretResponse,
)
def get_secret(
    username: UsernameStr = Query(..., example="user1"),
    current_user: dict = Depends(get_current_user),
):
    token_username = current_user.get("username")
    if token_username != username:
        # Prevent users from accessing others' secrets (CWE-863/CWE-284)
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    user = db_get_user_by_username(username)
    if not user:
        # Treat as unauthorized to avoid exposing which users exist
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    secret = db_get_secret(user_id=user["id"])
    # If no secret set, return empty string to meet the schema type
    return {"secret": secret if secret is not None else ""}

# ---------------------------
# Custom OpenAPI to match the provided schema more closely
# ---------------------------

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=APP_NAME,
        version=APP_VERSION,
        description=APP_DESCRIPTION,
        routes=app.routes,
    )
    # Add security scheme
    openapi_schema.setdefault("components", {}).setdefault("securitySchemes", {})
    openapi_schema["components"]["securitySchemes"]["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Set global security requirement
    openapi_schema["security"] = [{"bearerAuth": []}]

    # For /register and /login -> no security
    paths = openapi_schema.get("paths", {})
    if "/register" in paths and "post" in paths["/register"]:
        paths["/register"]["post"]["security"] = []
        # Align examples and response schemas
        paths["/register"]["post"]["responses"]["201"] = {
            "description": "Successful registration",
            "content": {
                "application/json": {
                    "schema": {"type": "object", "properties": {"message": {"type": "string", "example": "Registration successful"}}}
                }
            },
        }
        paths["/register"]["post"]["responses"]["400"] = {
            "description": "Bad Request",
            "content": {
                "application/json": {
                    "schema": {"type": "object", "properties": {"message": {"type": "string", "example": "Email already in use or invalid data"}}}
                }
            },
        }
        # Ensure requestBody example matches provided schema (already set by body examples)

    if "/login" in paths and "post" in paths["/login"]:
        paths["/login"]["post"]["security"] = []
        paths["/login"]["post"]["responses"]["200"] = {
            "description": "Successful login",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "token": {"type": "string", "example": "jwt-token-abc123"},
                            "message": {"type": "string", "example": "Login successful"},
                        },
                    }
                }
            },
        }
        paths["/login"]["post"]["responses"]["401"] = {
            "description": "Unauthorized",
            "content": {
                "application/json": {
                    "schema": {"type": "object", "properties": {"message": {"type": "string", "example": "Invalid email or password"}}}
                }
            },
        }

    if "/set_secret" in paths and "post" in paths["/set_secret"]:
        paths["/set_secret"]["post"]["responses"]["200"] = {
            "description": "Secret set successfully",
            "content": {
                "application/json": {
                    "schema": {"type": "object", "properties": {"message": {"type": "string", "example": "Secret has been set successfully"}}}
                }
            },
        }
        paths["/set_secret"]["post"]["responses"]["401"] = {
            "description": "Unauthorized",
            "content": {
                "application/json": {
                    "schema": {"type": "object", "properties": {"message": {"type": "string", "example": "Invalid authentication token"}}}
                }
            },
        }

    if "/get_secret" in paths and "get" in paths["/get_secret"]:
        paths["/get_secret"]["get"]["responses"]["200"] = {
            "description": "Secret retrieved successfully",
            "content": {
                "application/json": {
                    "schema": {"type": "object", "properties": {"secret": {"type": "string", "example": "The secret associated with the provided details"}}}
                }
            },
        }
        paths["/get_secret"]["get"]["responses"]["401"] = {
            "description": "Unauthorized",
            "content": {
                "application/json": {
                    "schema": {"type": "object", "properties": {"message": {"type": "string", "example": "Invalid authentication token"}}}
                }
            },
        }

    # Add tag metadata to align with provided schema if needed
    openapi_schema["tags"] = [
        {"name": "Authentication", "description": "Operations related to user authentication"}
    ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# ---------------------------
# Error Handlers (defensive)
# ---------------------------

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Ensure all HTTPExceptions return consistent JSON with a message field if provided as dict
    detail = exc.detail
    if isinstance(detail, dict) and "message" in detail:
        return fastapi_json_response(detail, status_code=exc.status_code)
    # Fallback generic message
    if exc.status_code == 401:
        return fastapi_json_response({"message": "Invalid authentication token"}, status_code=401)
    if exc.status_code == 400:
        return fastapi_json_response({"message": "Bad Request"}, status_code=400)
    return fastapi_json_response({"message": "Internal server error"}, status_code=exc.status_code)

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error: %s", exc)
    return fastapi_json_response({"message": "Internal server error"}, status_code=500)

def fastapi_json_response(data: dict, status_code: int = 200):
    # Helper to avoid importing Response classes at top-level for clarity
    from fastapi.responses import JSONResponse

    return JSONResponse(content=data, status_code=status_code)

# ---------------------------
# Entry Point
# ---------------------------

if __name__ == "__main__":
    # Start the Uvicorn server
    uvicorn.run(app, host="0.0.0.0", port=5000)