import os
import sqlite3
import logging
from typing import Optional, Dict, Any

from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Depends, HTTPException, Request, status, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware

from pydantic import BaseModel, Field, EmailStr, field_validator

from passlib.hash import pbkdf2_sha256
import jwt
import secrets


# ------------------------------------------------------------------------------
# Logging configuration
# ------------------------------------------------------------------------------
logger = logging.getLogger("secret_storage")
handler = logging.StreamHandler()
formatter = logging.Formatter(
    "%(asctime)s %(levelname)s [%(name)s] %(message)s"
)
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to a generated ephemeral secret for runtime; best practice is to
    # always supply APP_SECRET via environment for predictable JWT verification.
    APP_SECRET = secrets.token_urlsafe(64)
    logger.warning("APP_SECRET not set; using a generated ephemeral secret. Tokens will be invalid after restart.")

JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = 60

DB_FILE = "db.sqlite3"


# ------------------------------------------------------------------------------
# FastAPI app setup
# ------------------------------------------------------------------------------
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    contact={"name": "Secret Storage"},
    license_info={"name": "Proprietary"},
)

auth_scheme = HTTPBearer(auto_error=False)


# ------------------------------------------------------------------------------
# Security headers middleware
# ------------------------------------------------------------------------------
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # Add common security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        # HSTS is meaningful only over HTTPS, but harmless otherwise
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # Basic CSP for API responses; adjust as needed
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        return response


app.add_middleware(SecurityHeadersMiddleware)


# ------------------------------------------------------------------------------
# Database helpers
# ------------------------------------------------------------------------------
def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE, isolation_level=None, timeout=10)
    conn.row_factory = sqlite3.Row
    # Enforce foreign key constraints
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    try:
        conn = get_db_connection()
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    user_id INTEGER PRIMARY KEY,
                    secret_text TEXT NOT NULL,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
        conn.close()
        logger.info("Database initialized.")
    except Exception as e:
        logger.exception("Failed to initialize database: %s", e)
        raise


@app.on_event("startup")
def on_startup():
    init_db()


# ------------------------------------------------------------------------------
# Pydantic models
# ------------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., examples=["user1"])
    password: str = Field(..., min_length=8, examples=["newUserPassword"])

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        # Restrict to alphanumeric and underscore for safety, length 3..30
        if not (3 <= len(v) <= 30):
            raise ValueError("Invalid username length")
        for ch in v:
            if not (ch.isalnum() or ch == "_"):
                raise ValueError("Username must be alphanumeric or underscore")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return v


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user1@example.com"])
    password: str = Field(..., examples=["pass1"])

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return v.strip()


class SetSecretRequest(BaseModel):
    username: str = Field(..., examples=["user1"])
    secret: str = Field(..., min_length=1, examples=["mySecret"])

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not (3 <= len(v) <= 30):
            raise ValueError("Invalid username length")
        for ch in v:
            if not (ch.isalnum() or ch == "_"):
                raise ValueError("Username must be alphanumeric or underscore")
        return v

    @field_validator("secret")
    @classmethod
    def validate_secret(cls, v: str) -> str:
        return v.strip()


# ------------------------------------------------------------------------------
# JWT utilities and authentication dependency
# ------------------------------------------------------------------------------
def create_jwt_token(user_id: int, username: str, email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXP_MINUTES)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_jwt_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})


def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(auth_scheme)) -> Dict[str, Any]:
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    payload = decode_jwt_token(token)
    user_id = payload.get("sub")
    username = payload.get("username")
    email = payload.get("email")
    if not user_id or not username or not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    # Verify user still exists and data matches
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT id, username, email FROM users WHERE id = ?",
            (int(user_id),),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        if row["username"] != username or row["email"] != email:
            # Token does not match current user data; prevent confused deputy (CWE-863)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        return {"id": row["id"], "username": row["username"], "email": row["email"]}
    finally:
        conn.close()


# ------------------------------------------------------------------------------
# Exception handling (CWE-703 robust handling)
# ------------------------------------------------------------------------------
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception: %s", exc)
    # Generic error response; do not leak internal details
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# ------------------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------------------
@app.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    summary="User registration",
    description="Register a new user with email, username and password.",
    tags=["Authentication"],
)
def register(body: RegisterRequest):
    # Normalize email to lowercase to avoid duplicates with case differences
    email_norm = body.email.lower()
    username_norm = body.username

    conn = get_db_connection()
    try:
        # Check for duplicates securely (CWE-89 mitigated via parameterized SQL)
        existing = conn.execute(
            "SELECT id FROM users WHERE email = ? OR username = ?",
            (email_norm, username_norm),
        ).fetchone()
        if existing:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})

        # Hash password securely (CWE-522 - do not store plaintext)
        password_hash = pbkdf2_sha256.hash(body.password)

        conn.execute(
            "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
            (email_norm, username_norm, password_hash),
        )
        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Registration failed: %s", e)
        # Return a 400 per schema for invalid data scenarios
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
    finally:
        conn.close()


@app.post(
    "/login",
    status_code=status.HTTP_200_OK,
    summary="User login",
    description="Authenticate a user with email and password.",
    tags=["Authentication"],
)
def login(body: LoginRequest):
    email_norm = body.email.lower()
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT id, username, email, password_hash FROM users WHERE email = ?",
            (email_norm,),
        ).fetchone()
        if not row:
            # Do not reveal whether email exists (CWE-522 - avoid information disclosure)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

        if not pbkdf2_sha256.verify(body.password, row["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

        token = create_jwt_token(row["id"], row["username"], row["email"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Login error: %s", e)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
    finally:
        conn.close()


@app.post(
    "/set_secret",
    status_code=status.HTTP_200_OK,
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(body: SetSecretRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    try:
        # Authorization check: ensure the provided username matches the authenticated user (CWE-284, CWE-863)
        if body.username != current_user["username"]:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

        conn = get_db_connection()
        try:
            # Upsert secret for the user (CWE-89 prevented via parameterized query)
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret_text, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret_text = excluded.secret_text,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (current_user["id"], body.secret),
            )
            return {"message": "Secret has been set successfully"}
        finally:
            conn.close()
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error setting secret: %s", e)
        # On unexpected errors, return 500; but schema expects 401 for auth issues and 200 for success.
        # We return 500 generic error to avoid leaking details.
        return JSONResponse(status_code=500, content={"message": "Internal server error"})


@app.get(
    "/get_secret",
    status_code=status.HTTP_200_OK,
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(username: str = Query(..., examples=["user1"]), current_user: Dict[str, Any] = Depends(get_current_user)):
    try:
        # Authorization check: ensure the requested username matches the authenticated user (CWE-284, CWE-863)
        if username.strip() != current_user["username"]:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

        conn = get_db_connection()
        try:
            row = conn.execute(
                """
                SELECT s.secret_text
                FROM secrets s
                JOIN users u ON u.id = s.user_id
                WHERE u.username = ?
                """,
                (current_user["username"],),
            ).fetchone()
            secret_text = row["secret_text"] if row else ""
            return {"secret": secret_text}
        finally:
            conn.close()
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error retrieving secret: %s", e)
        return JSONResponse(status_code=500, content={"message": "Internal server error"})


# ------------------------------------------------------------------------------
# Uvicorn entrypoint
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5000)