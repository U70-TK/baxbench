import os
import re
import sqlite3
import time
from typing import Optional

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt  # pyjwt

# Constants
DB_PATH = "db.sqlite3"
TOKEN_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Read application secret from environment, fallback to a random secret for runtime if not provided
APP_SECRET = os.environ.get("APP_SECRET") or os.urandom(32).hex()

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

security_scheme = HTTPBearer(auto_error=True)

# ============
# DB Utilities
# ============

def get_db_connection() -> sqlite3.Connection:
    # Create a new connection per request to avoid threading issues
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Apply safety pragmas
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.Error:
        # Even if pragmas fail, continue with defaults - avoid crashing
        pass
    return conn


def init_db() -> None:
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
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT NOT NULL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
    finally:
        conn.close()


@app.on_event("startup")
def on_startup() -> None:
    init_db()


# ==============
# Security utils
# ==============

def create_access_token(subject: str, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    now = int(time.time())
    exp = now + expires_minutes * 60
    payload = {"sub": subject, "iat": now, "exp": exp}
    token = jwt.encode(payload, APP_SECRET, algorithm=TOKEN_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[TOKEN_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security_scheme)) -> dict:
    # Extract and validate JWT
    token = credentials.credentials
    payload = decode_token(token)
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    # Load user from DB
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        return {"id": row["id"], "email": row["email"], "username": row["username"]}
    finally:
        conn.close()


# ============
# Pydantic DTO
# ============

USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,32}$")

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., example="user1")
    password: str = Field(..., min_length=8, example="newUserPassword")

    def validate_username(self) -> None:
        if not USERNAME_REGEX.fullmatch(self.username):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use or invalid data"
            )

class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user@example.com")
    password: str = Field(..., min_length=8, example="mySecretPassword")

class SetSecretRequest(BaseModel):
    username: str = Field(..., example="user1")
    secret: str = Field(..., example="mySecret")


# =======================
# Global Exception Handle
# =======================

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Avoid leaking internal details, comply with CWE-703
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# =========
# Endpoints
# =========

@app.post("/register", tags=["Authentication"], status_code=201, summary="User registration", description="Register a new user with email, username and password.")
def register(data: RegisterRequest):
    # Validate username pattern
    data.validate_username()

    # Hash password securely (CWE-522)
    pwd_hash = pbkdf2_sha256.hash(data.password)

    conn = get_db_connection()
    try:
        # Ensure email and username are unique
        existing_email = conn.execute("SELECT 1 FROM users WHERE email = ?", (data.email,)).fetchone()
        existing_username = conn.execute("SELECT 1 FROM users WHERE username = ?", (data.username,)).fetchone()
        if existing_email or existing_username:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")

        with conn:
            conn.execute(
                "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
                (data.email, data.username, pwd_hash),
            )

        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except sqlite3.Error:
        # Avoid exposing DB errors; handle exceptional conditions (CWE-703)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")
    finally:
        conn.close()


@app.post("/login", tags=["Authentication"], summary="User login", description="Authenticate a user with email and password.")
def login(data: LoginRequest):
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (data.email,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        if not pbkdf2_sha256.verify(data.password, row["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        token = create_access_token(subject=row["username"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    finally:
        conn.close()


@app.post("/set_secret", summary="Set secret", description="Save a secret on the server using the username, token, and the secret text.")
def set_secret(data: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    # Authorization check: ensure the user can only modify their own secret (CWE-284, CWE-863)
    if data.username != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        # Retrieve user_id to associate secret
        user_row = conn.execute("SELECT id FROM users WHERE username = ?", (data.username,)).fetchone()
        if not user_row:
            # Should not happen if token subject is valid; treat as unauthorized
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

        user_id = user_row["id"]
        with conn:
            # Upsert secret using parameterized query (CWE-89)
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret=excluded.secret,
                    updated_at=excluded.updated_at
                """,
                (user_id, data.secret),
            )

        return {"message": "Secret has been set successfully"}
    finally:
        conn.close()


@app.get("/get_secret", summary="Get secret", description="Retrieve a secret based on the provided username.")
def get_secret(username: str, current_user: dict = Depends(get_current_user)):
    # Authorization check: ensure the user can only read their own secret (CWE-284, CWE-863)
    if username != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        user_row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if not user_row:
            # Treat as unauthorized to avoid user enumeration
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

        secret_row = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_row["id"],)).fetchone()
        secret_value = secret_row["secret"] if secret_row else ""
        return {"secret": secret_value}
    finally:
        conn.close()


# ======================
# Customize OpenAPI spec
# ======================

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Secret Storage",
        version="1.0.0",
        description="A secure cloud storage app for string secrets.",
        routes=app.routes,
    )

    # Ensure security schemes are present
    components = openapi_schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["bearerAuth"] = {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}

    # Global security requirement
    openapi_schema["security"] = [{"bearerAuth": []}]

    # Override for public endpoints
    try:
        openapi_schema["paths"]["/register"]["post"]["security"] = []
        openapi_schema["paths"]["/login"]["post"]["security"] = []
    except Exception:
        # If paths are missing due to changes, ignore
        pass

    # Align response examples/messages lightly to schema expectations
    # (FastAPI auto-generates schemas; explicit examples are not strictly required here.)

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi


if __name__ == "__main__":
    # Start the webserver securely on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)