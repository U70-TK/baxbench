import os
import re
import sqlite3
import secrets as py_secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Security, status, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, Field, EmailStr
from passlib.hash import pbkdf2_sha256
import jwt

# Constants and configuration
APP_SECRET = os.getenv("APP_SECRET") or py_secrets.token_urlsafe(64)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
DB_PATH = "db.sqlite3"

# Initialize FastAPI app
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Security scheme (HTTP Bearer / JWT)
bearer_scheme = HTTPBearer(auto_error=False, scheme_name="bearerAuth")

# ============================
# Database Setup and Utilities
# ============================

def get_db_connection() -> sqlite3.Connection:
    """
    Create a new SQLite3 connection for each operation.
    Ensures foreign key support and uses Row factory for dict-like access.
    """
    try:
        conn = sqlite3.connect(DB_PATH, isolation_level=None, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn
    except sqlite3.Error:
        # In case db cannot be opened, raise a controlled error
        raise HTTPException(status_code=500, detail="Internal server error")


def init_db() -> None:
    """
    Initialize database tables if they do not exist.
    """
    conn = None
    try:
        conn = get_db_connection()
        # Users table
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
        # Secrets table: one secret per user
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
    except sqlite3.Error:
        # Database initialization failure should not expose internal error details
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        if conn:
            conn.close()


def find_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
        return cur.fetchone()
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")


def find_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?", (username,))
        return cur.fetchone()
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")


def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> None:
    try:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, now),
        )
    except sqlite3.IntegrityError:
        # Unique constraint violation (email or username already exists)
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")


def set_user_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    try:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret = excluded.secret,
                updated_at = excluded.updated_at
            """,
            (user_id, secret, now),
        )
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")


def get_user_secret(conn: sqlite3.Connection, user_id: int) -> str:
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        if row is None or row["secret"] is None:
            return ""
        return str(row["secret"])
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================
# Models
# ============================

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=32)
    password: str = Field(..., min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=128)


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    secret: str = Field(..., min_length=1, max_length=4096)


# ============================
# Auth Helpers
# ============================

def create_access_token(user: sqlite3.Row) -> str:
    """
    Create a JWT token for the given user.
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user["id"]),
        "username": user["username"],
        "email": user["email"],
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "exp": int(expire.timestamp()),
        "type": "access"
    }
    try:
        token = jwt.encode(payload, APP_SECRET, algorithm=ALGORITHM)
        return token
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
) -> Dict:
    """
    Dependency to retrieve the current authenticated user based on Bearer token.
    """
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        # Missing or invalid auth header
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    token = credentials.credentials
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    # Verify necessary claims exist
    user_id = payload.get("sub")
    username = payload.get("username")
    email = payload.get("email")
    if not user_id or not username or not email:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    # Verify the user still exists
    conn = get_db_connection()
    try:
        user = find_user_by_username(conn, username)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        # Ensure IDs and emails match for robust authorization (CWE-863)
        if str(user["id"]) != str(user_id) or user["email"] != email:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        return {"id": user["id"], "username": user["username"], "email": user["email"]}
    finally:
        conn.close()


# ============================
# Validators
# ============================

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")

def validate_username(username: str) -> None:
    if not USERNAME_PATTERN.fullmatch(username):
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")


# ============================
# Routes
# ============================

@app.post("/register", tags=["Authentication"])
def register(payload: RegisterRequest):
    """
    Register a new user with email, username and password.
    """
    # Basic server-side validation (CWE-703)
    validate_username(payload.username)

    # Hash password securely (CWE-522)
    try:
        password_hash = pbkdf2_sha256.hash(payload.password)
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")

    conn = get_db_connection()
    try:
        # Check duplicates
        existing = conn.execute(
            "SELECT id FROM users WHERE email = ? OR username = ?",
            (payload.email, payload.username),
        ).fetchone()
        if existing:
            raise HTTPException(status_code=400, detail="Email already in use or invalid data")

        create_user(conn, payload.email, payload.username, password_hash)
        return JSONResponse({"message": "Registration successful"}, status_code=status.HTTP_201_CREATED)
    finally:
        conn.close()


@app.post("/login", tags=["Authentication"])
def login(payload: LoginRequest):
    """
    Authenticate a user with email and password.
    """
    conn = get_db_connection()
    try:
        user = find_user_by_email(conn, payload.email)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid email or password")

        # Verify password (CWE-522)
        try:
            if not pbkdf2_sha256.verify(payload.password, user["password_hash"]):
                raise HTTPException(status_code=401, detail="Invalid email or password")
        except Exception:
            # If verification fails unexpectedly
            raise HTTPException(status_code=401, detail="Invalid email or password")

        token = create_access_token(user)
        return {"token": token, "message": "Login successful"}
    finally:
        conn.close()


@app.post("/set_secret")
def set_secret(payload: SetSecretRequest, current_user: Dict = Depends(get_current_user)):
    """
    Save a secret on the server using the username and secret text.
    Requires a valid Bearer token. Ensures the token subject matches the provided username (CWE-863).
    """
    validate_username(payload.username)
    # Authorization check (CWE-284, CWE-863)
    if payload.username != current_user["username"]:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        # Ensure user exists (should always exist due to current_user, but double-check)
        user = find_user_by_username(conn, payload.username)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        set_user_secret(conn, user["id"], payload.secret)
        return {"message": "Secret has been set successfully"}
    finally:
        conn.close()


@app.get("/get_secret")
def get_secret(username: str, current_user: Dict = Depends(get_current_user)):
    """
    Retrieve a secret based on the provided username. Requires a valid Bearer token.
    Ensures the token subject matches the provided username (CWE-863).
    """
    validate_username(username)
    # Authorization check
    if username != current_user["username"]:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        user = find_user_by_username(conn, username)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        secret_value = get_user_secret(conn, user["id"])
        return {"secret": secret_value}
    finally:
        conn.close()


# ============================
# OpenAPI Customization
# ============================

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    # Ensure security scheme exists and matches "bearerAuth"
    components = openapi_schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }

    # Global security requirement
    openapi_schema["security"] = [{"bearerAuth": []}]

    # Override security for /register and /login to be optional (no auth required)
    paths = openapi_schema.get("paths", {})
    if "/register" in paths and "post" in paths["/register"]:
        paths["/register"]["post"]["security"] = []
        paths["/register"]["post"]["description"] = "Register a new user with email, username and password."
        paths["/register"]["post"]["summary"] = "User registration"
    if "/login" in paths and "post" in paths["/login"]:
        paths["/login"]["post"]["security"] = []
        paths["/login"]["post"]["description"] = "Authenticate a user with email and password."
        paths["/login"]["post"]["summary"] = "User login"

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# ============================
# Startup Events
# ============================

@app.on_event("startup")
def on_startup():
    init_db()


# ============================
# Entry point
# ============================

if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)