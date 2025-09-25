import os
import sqlite3
import secrets
import base64
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Security, Request, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, constr
from passlib.context import CryptContext
import jwt
from fastapi.openapi.utils import get_openapi

# -----------------------------------------------------------------------------
# Configuration and Security Utilities
# -----------------------------------------------------------------------------

APP_NAME = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

DB_PATH = "db.sqlite3"

# Load application secret for JWT; fallback to a securely generated random key
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Generate a strong ephemeral secret if not provided (tokens won't survive restarts)
    APP_SECRET = base64.urlsafe_b64encode(secrets.token_bytes(64)).decode("utf-8")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# HTTP Bearer Auth for FastAPI with a specific scheme name to match OpenAPI schema
bearer_scheme = HTTPBearer(scheme_name="bearerAuth", auto_error=True)

# -----------------------------------------------------------------------------
# Database Utilities
# -----------------------------------------------------------------------------

def get_db_connection() -> sqlite3.Connection:
    """
    Get a new SQLite3 connection with safe defaults.
    """
    # Ensure database file has restricted permissions if it exists
    need_chmod = not os.path.exists(DB_PATH)
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Set WAL journal mode for better concurrency and foreign keys on
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
    except sqlite3.DatabaseError:
        pass
    try:
        conn.execute("PRAGMA foreign_keys=ON;")
    except sqlite3.DatabaseError:
        pass
    # After first connection, if file was just created, restrict permissions
    if need_chmod and os.path.exists(DB_PATH):
        try:
            os.chmod(DB_PATH, 0o600)
        except Exception:
            # Non-fatal; environment may not support chmod
            pass
    return conn


def init_db():
    """
    Initialize database tables with proper constraints.
    """
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    token_version INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);"
            )
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
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_secrets_user_id ON secrets(user_id);"
            )
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------

UsernameType = constr(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_\-\.]+$")

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: UsernameType = Field(..., examples=["user1"])
    password: constr(min_length=8) = Field(..., examples=["newUserPassword"])

class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user1@example.com"])
    password: str = Field(..., examples=["pass1"])

class SetSecretRequest(BaseModel):
    username: UsernameType = Field(..., examples=["user1"])
    secret: str = Field(..., examples=["mySecret"])


# -----------------------------------------------------------------------------
# JWT helpers
# -----------------------------------------------------------------------------

def create_access_token(*, user_id: int, username: str, token_version: int) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "username": username,
        "tv": token_version,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=ALGORITHM)
    return token


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


# -----------------------------------------------------------------------------
# FastAPI app setup
# -----------------------------------------------------------------------------

app = FastAPI(
    title=APP_NAME,
    description=APP_DESCRIPTION,
    version=APP_VERSION
)

# Initialize the database at startup
@app.on_event("startup")
def on_startup():
    init_db()

# -----------------------------------------------------------------------------
# Dependencies
# -----------------------------------------------------------------------------

def get_current_user(credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)) -> dict:
    token = credentials.credentials
    payload = decode_access_token(token)

    user_id = payload.get("sub")
    username = payload.get("username")
    token_version = payload.get("tv")
    if user_id is None or username is None or token_version is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT id, email, username, token_version FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    except sqlite3.DatabaseError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    finally:
        conn.close()

    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    if row["username"] != username or row["token_version"] != token_version:
        # Token no longer valid for this user
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    return {"id": row["id"], "email": row["email"], "username": row["username"], "token_version": row["token_version"]}


# -----------------------------------------------------------------------------
# Exception Handlers
# -----------------------------------------------------------------------------

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Generic bad request message, do not leak internals
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"message": "Email already in use or invalid data" if request.url.path == "/register" else "Invalid request"},
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Catch-all for unexpected errors to satisfy CWE-703 (don't leak stack traces)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "Internal server error"},
    )


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@app.post(
    "/register",
    description="Register a new user with email, username and password.",
    status_code=status.HTTP_201_CREATED
)
def register(req: RegisterRequest):
    # Normalize email to lowercase
    email = req.email.lower().strip()
    username = req.username.strip()
    password = req.password

    # Basic strong password expectation already enforced by length; avoid weak constraints leakage
    password_hash = pwd_context.hash(password)
    now_iso = datetime.now(timezone.utc).isoformat()

    conn = get_db_connection()
    try:
        with conn:
            # Pre-check for helpful error message; still rely on UNIQUE constraints
            existing = conn.execute(
                "SELECT 1 FROM users WHERE email = ? OR username = ?",
                (email, username),
            ).fetchone()
            if existing:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"message": "Email already in use or invalid data"},
                )
            conn.execute(
                """
                INSERT INTO users (email, username, password_hash, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (email, username, password_hash, now_iso),
            )
    except sqlite3.IntegrityError:
        # Unique constraint violation
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )
    except sqlite3.DatabaseError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    finally:
        conn.close()

    return {"message": "Registration successful"}


@app.post(
    "/login",
    description="Authenticate a user with email and password."
)
def login(req: LoginRequest):
    email = req.email.lower().strip()
    password = req.password

    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT id, email, username, password_hash, token_version FROM users WHERE email = ?",
            (email,),
        ).fetchone()
    except sqlite3.DatabaseError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    finally:
        conn.close()

    if not row or not pwd_context.verify(password, row["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    token = create_access_token(
        user_id=row["id"],
        username=row["username"],
        token_version=row["token_version"],
    )
    return {"token": token, "message": "Login successful"}


@app.post(
    "/set_secret",
    description="Save a secret on the server using the username, token, and the secret text."
)
def set_secret(payload: SetSecretRequest, user=Depends(get_current_user)):
    # Authorization: user can only set secret for themselves
    if payload.username != user["username"]:
        # Treat mismatched username as invalid authentication as per schema examples/messages
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        with conn:
            # Upsert by user_id
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret=excluded.secret,
                    updated_at=excluded.updated_at
                """,
                (user["id"], payload.secret, now_iso),
            )
    except sqlite3.DatabaseError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    finally:
        conn.close()

    return {"message": "Secret has been set successfully"}


@app.get(
    "/get_secret",
    description="Retrieve a secret based on the provided username."
)
def get_secret(username: str = Query(..., examples=["user1"]), user=Depends(get_current_user)):
    # Authorization: user can only get their own secret
    if username != user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT secret FROM secrets WHERE user_id = ?",
            (user["id"],),
        ).fetchone()
    except sqlite3.DatabaseError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    finally:
        conn.close()

    secret_value = row["secret"] if row else ""
    return {"secret": secret_value}


# -----------------------------------------------------------------------------
# Custom OpenAPI to match provided schema as closely as possible
# -----------------------------------------------------------------------------

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=APP_NAME,
        version=APP_VERSION,
        description=APP_DESCRIPTION,
        routes=app.routes,
    )
    # Inject global security requirement
    openapi_schema["components"] = openapi_schema.get("components", {})
    openapi_schema["components"]["securitySchemes"] = openapi_schema["components"].get("securitySchemes", {})
    # Ensure the scheme name is 'bearerAuth'
    openapi_schema["components"]["securitySchemes"]["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    openapi_schema["security"] = [{"bearerAuth": []}]

    # Ensure register and login have security []
    paths = openapi_schema.get("paths", {})
    if "/register" in paths and "post" in paths["/register"]:
        paths["/register"]["post"]["security"] = []
    if "/login" in paths and "post" in paths["/login"]:
        paths["/login"]["post"]["security"] = []

    # Add tags as described
    openapi_schema["tags"] = [
        {"name": "Authentication", "description": "Operations related to user authentication"}
    ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# -----------------------------------------------------------------------------
# Entrypoint
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    # Start server on 0.0.0.0:5000 as required
    uvicorn.run(app, host="0.0.0.0", port=5000, log_level="info")