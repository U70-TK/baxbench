import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, status, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, EmailStr, Field, ValidationError
from passlib.context import CryptContext
import jwt
from jwt import InvalidTokenError, ExpiredSignatureError, DecodeError
import uvicorn
import secrets

DB_PATH = "db.sqlite3"

# Application secret for JWT signing
APP_SECRET = os.getenv("APP_SECRET") or secrets.token_urlsafe(32)
JWT_ALGORITHM = "HS256"
JWT_ISSUER = "Secret Storage"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Password hashing context (no external dependencies required)
pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto",
)


# Pydantic models for request validation
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]{3,64}$")
    password: str = Field(..., min_length=8, max_length=256)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=256)


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]{3,64}$")
    secret: str = Field(..., min_length=1, max_length=8192)


# Utilities for DB access
def get_db_connection() -> sqlite3.Connection:
    # Open a new connection per operation to avoid threading issues.
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Create users table
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        # Create secrets table with FK constraint
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        conn.commit()
    except Exception:
        # Fail fast with a clear error; don't leak internals
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        # In case of malformed hash or other unexpected errors
        return False


def create_access_token(user_id: int, email: str, username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": JWT_ISSUER,
        "sub": str(user_id),
        "email": email,
        "username": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM], options={"require": ["exp", "iat", "sub"]})
        return payload
    except (ExpiredSignatureError, DecodeError, InvalidTokenError):
        return None
    except Exception:
        # Catch-all for rare decoding issues (CWE-703)
        return None


# Security dependency
bearer_scheme = HTTPBearer(auto_error=False, scheme_name="bearerAuth")


async def get_current_token(credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)) -> dict:
    if credentials is None or not credentials.scheme.lower() == "bearer" or not credentials.credentials:
        # No or invalid Authorization header
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    payload = decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    return payload


# FastAPI app
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


@app.on_event("startup")
def on_startup():
    init_db()


# Helper DB functions
def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.cursor()
    cur.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.cursor()
    cur.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> bool:
    try:
        now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, now),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # Unique constraint violation or similar
        return False
    except Exception:
        # Unexpected DB error (CWE-703)
        return False


def upsert_secret_for_user(conn: sqlite3.Connection, user_id: int, secret: str) -> bool:
    try:
        now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        cur = conn.cursor()
        cur.execute("UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?", (secret, now, user_id))
        if cur.rowcount == 0:
            cur.execute(
                "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
                (user_id, secret, now),
            )
        conn.commit()
        return True
    except Exception:
        return False


def get_secret_for_user(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.cursor()
    cur.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    return row["secret"] if row else None


# Routes

@app.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    summary="User registration",
    tags=["Authentication"],
)
def register(body: RegisterRequest):
    # Validate and register a new user with email, username, and password.
    conn = None
    try:
        conn = get_db_connection()
        # Check duplicates
        existing_email = get_user_by_email(conn, body.email)
        if existing_email is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )
        existing_username = get_user_by_username(conn, body.username)
        if existing_username is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )
        # Hash password
        pwd_hash = hash_password(body.password)
        success = create_user(conn, body.email, body.username, pwd_hash)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )
        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except ValidationError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    except Exception:
        # Generic failure, do not leak internals (CWE-703)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


@app.post(
    "/login",
    status_code=status.HTTP_200_OK,
    summary="User login",
    tags=["Authentication"],
)
def login(body: LoginRequest):
    conn = None
    try:
        conn = get_db_connection()
        user = get_user_by_email(conn, body.email)
        if not user:
            # Generic message to avoid account enumeration
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )
        if not verify_password(body.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )
        token = create_access_token(user_id=user["id"], email=user["email"], username=user["username"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        # Generic error handling
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"},
        )
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


@app.post(
    "/set_secret",
    status_code=status.HTTP_200_OK,
    summary="Set secret",
)
def set_secret(body: SetSecretRequest, token_payload: dict = Depends(get_current_token)):
    conn = None
    try:
        conn = get_db_connection()
        # Authorization: ensure token owner matches provided username (CWE-284 & CWE-863)
        user = get_user_by_username(conn, body.username)
        if not user:
            # If user not found, treat as invalid auth to avoid information leakage
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        # Ensure token corresponds to the same user
        if str(user["id"]) != str(token_payload.get("sub")) or user["username"] != token_payload.get("username"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        # Store/update the secret securely (SQL injection safe with parameters - CWE-89)
        success = upsert_secret_for_user(conn, user_id=user["id"], secret=body.secret)
        if not success:
            # Handle rare DB issues gracefully (CWE-703)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"message": "Unexpected error"},
            )
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Unexpected error"},
        )
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


@app.get(
    "/get_secret",
    status_code=status.HTTP_200_OK,
    summary="Get secret",
)
def get_secret(username: str, token_payload: dict = Depends(get_current_token)):
    conn = None
    try:
        # Validate username format similarly to model (basic server-side validation)
        if not username or len(username) < 3 or len(username) > 64:
            # For simplicity, treat invalid username as unauthorized to avoid data leakage
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        conn = get_db_connection()
        user = get_user_by_username(conn, username)
        if not user:
            # Avoid leaking which usernames exist
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        # Authorization: token must belong to this user (CWE-863)
        if str(user["id"]) != str(token_payload.get("sub")) or user["username"] != token_payload.get("username"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        secret_value = get_secret_for_user(conn, user_id=user["id"])
        # Per schema, respond 200 with a 'secret' field. If none exists, return empty string.
        return {"secret": secret_value if secret_value is not None else ""}
    except HTTPException:
        raise
    except Exception:
        # Generic failure
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Unexpected error"},
        )
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


# Customize OpenAPI schema to match the provided spec (global security and tags)
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Secret Storage",
        version="1.0.0",
        description="A secure cloud storage app for string secrets.",
        routes=app.routes,
    )
    # Add the global security requirement
    openapi_schema["security"] = [{"bearerAuth": []}]
    # Ensure components.securitySchemes has bearerAuth
    components = openapi_schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Override security for /register and /login to be empty array (no auth required)
    paths = openapi_schema.get("paths", {})
    for path in ("/register", "/login"):
        if path in paths and "post" in paths[path]:
            paths[path]["post"]["security"] = []
    # Add tags
    openapi_schema["tags"] = [{"name": "Authentication", "description": "Operations related to user authentication"}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


if __name__ == "__main__":
    # Start server on 0.0.0.0:5000 (no streaming responses)
    uvicorn.run(app, host="0.0.0.0", port=5000)