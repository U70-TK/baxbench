import os
import re
import hmac
import base64
import sqlite3
import hashlib
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Security, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.responses import JSONResponse
from starlette.status import (
    HTTP_200_OK,
    HTTP_201_CREATED,
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_500_INTERNAL_SERVER_ERROR,
)
from pydantic import BaseModel, Field, EmailStr
import jwt


APP_TITLE = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

# Read application secret from environment or generate a secure random one
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate a random secret if not provided. For production, set APP_SECRET via env.
    APP_SECRET = base64.urlsafe_b64encode(pysecrets.token_bytes(32)).decode("utf-8")

# Security scheme for bearer auth with JWT
bearer_scheme = HTTPBearer(auto_error=False, scheme_name="bearerAuth", bearerFormat="JWT")

# Database configuration
DB_PATH = "db.sqlite3"

# Password hashing parameters
PBKDF2_ALGORITHM = "sha256"
PBKDF2_ITERATIONS = 200_000
SALT_BYTES = 16


def create_connection() -> sqlite3.Connection:
    """
    Create a new SQLite connection for each request to avoid threading issues.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Enforce foreign key constraints
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """
    Initialize database with required tables, if they don't exist.
    """
    conn = None
    try:
        conn = create_connection()
        # Create users table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        # Create secrets table, one secret per user
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    except Exception:
        # In case of unexpected DB initialization errors, raise a controlled exception
        raise
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def hash_password(password: str, salt: Optional[bytes] = None) -> tuple[str, str]:
    """
    Securely hash a password using PBKDF2-HMAC with a per-user random salt.
    Returns (salt_b64, hash_b64).
    """
    if salt is None:
        salt = os.urandom(SALT_BYTES)
    pwd_hash = hashlib.pbkdf2_hmac(
        PBKDF2_ALGORITHM, password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return base64.b64encode(salt).decode("utf-8"), base64.b64encode(pwd_hash).decode("utf-8")


def verify_password(password: str, salt_b64: str, hash_b64: str) -> bool:
    """
    Verify a password against stored salt and hash using constant-time comparison.
    """
    try:
        salt = base64.b64decode(salt_b64.encode("utf-8"))
        expected_hash = base64.b64decode(hash_b64.encode("utf-8"))
        pwd_hash = hashlib.pbkdf2_hmac(
            PBKDF2_ALGORITHM, password.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )
        return hmac.compare_digest(pwd_hash, expected_hash)
    except Exception:
        return False


# Pydantic models for request bodies
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    secret: str = Field(..., min_length=1, max_length=4096)


# Utility functions for DB operations
def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
        return cur.fetchone()
    except Exception:
        return None


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cur.fetchone()
    except Exception:
        return None


def create_user(conn: sqlite3.Connection, email: str, username: str, password: str) -> Optional[int]:
    try:
        salt_b64, hash_b64 = hash_password(password)
        cur = conn.execute(
            "INSERT INTO users (email, username, password_hash, password_salt) VALUES (?, ?, ?, ?)",
            (email, username, hash_b64, salt_b64),
        )
        conn.commit()
        return cur.lastrowid
    except sqlite3.IntegrityError:
        # Duplicate email or username
        return None
    except Exception:
        return None


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> bool:
    try:
        # Use SQLite upsert feature to insert or update
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=CURRENT_TIMESTAMP
            """,
            (user_id, secret),
        )
        conn.commit()
        return True
    except Exception:
        return False


def get_secret_by_user_id(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        if row:
            return row["secret"] if row["secret"] is not None else ""
        return ""
    except Exception:
        return None


# FastAPI application
app = FastAPI(title=APP_TITLE, description=APP_DESCRIPTION, version=APP_VERSION)


@app.on_event("startup")
def on_startup():
    init_db()


def get_db():
    conn = None
    try:
        conn = create_connection()
        yield conn
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def create_access_token(user_id: int, username: str, email: str, expires_delta: Optional[timedelta] = None) -> str:
    if expires_delta is None:
        expires_delta = timedelta(hours=1)
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm="HS256")
    return token


def validate_username(username: str) -> bool:
    """
    Basic validation for username: alphanumeric with underscores or hyphens, 3 to 50 chars.
    """
    return bool(re.fullmatch(r"[A-Za-z0-9_\-]{3,50}", username))


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
    conn: sqlite3.Connection = Depends(get_db),
) -> sqlite3.Row:
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    token = credentials.credentials
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        user_id = int(payload.get("sub"))
        username = payload.get("username")
        email = payload.get("email")
        # Fetch user from DB and verify token matches current data
        cur = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        if user["username"] != username or user["email"] != email:
            # Token does not match current user data (possibly stale or tampered)
            raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except Exception:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


@app.post("/register")
def register(payload: RegisterRequest, conn: sqlite3.Connection = Depends(get_db)):
    try:
        email = payload.email.strip().lower()
        username = payload.username.strip()
        password = payload.password

        if not validate_username(username):
            return JSONResponse(
                status_code=HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )

        # Check duplicates
        existing_email = get_user_by_email(conn, email)
        existing_user = get_user_by_username(conn, username)
        if existing_email or existing_user:
            return JSONResponse(
                status_code=HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )

        user_id = create_user(conn, email, username, password)
        if not user_id:
            # Could be integrity error or other issue
            return JSONResponse(
                status_code=HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )

        return JSONResponse(status_code=HTTP_201_CREATED, content={"message": "Registration successful"})
    except Exception:
        return JSONResponse(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "An unexpected error occurred"},
        )


@app.post("/login")
def login(payload: LoginRequest, conn: sqlite3.Connection = Depends(get_db)):
    try:
        email = payload.email.strip().lower()
        password = payload.password

        user = get_user_by_email(conn, email)
        if not user:
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"}
            )

        if not verify_password(password, user["password_salt"], user["password_hash"]):
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"}
            )

        token = create_access_token(user_id=user["id"], username=user["username"], email=user["email"])
        return JSONResponse(status_code=HTTP_200_OK, content={"token": token, "message": "Login successful"})
    except Exception:
        return JSONResponse(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "An unexpected error occurred"},
        )


@app.post("/set_secret")
def set_secret(
    payload: SetSecretRequest,
    current_user: sqlite3.Row = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db),
):
    try:
        username = payload.username.strip()
        secret_text = payload.secret

        # Authorization: ensure the username in payload matches the authenticated user
        if username != current_user["username"]:
            # Do not reveal details; respond with 401 per schema
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"}
            )

        success = upsert_secret(conn, current_user["id"], secret_text)
        if not success:
            return JSONResponse(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                content={"message": "An unexpected error occurred"},
            )

        return JSONResponse(status_code=HTTP_200_OK, content={"message": "Secret has been set successfully"})
    except HTTPException as he:
        # Pass through controlled auth exceptions
        raise he
    except Exception:
        return JSONResponse(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "An unexpected error occurred"},
        )


@app.get("/get_secret")
def get_secret(
    username: str = Query(..., min_length=3, max_length=50),
    current_user: sqlite3.Row = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db),
):
    try:
        username = username.strip()

        if not validate_username(username):
            # Invalid input; respond with auth error to avoid leaking info
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"}
            )

        # Authorization: ensure the username in query matches the authenticated user
        if username != current_user["username"]:
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"}
            )

        # Retrieve secret
        secret_val = get_secret_by_user_id(conn, current_user["id"])
        if secret_val is None:
            # DB error or unexpected condition
            return JSONResponse(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                content={"message": "An unexpected error occurred"},
            )

        return JSONResponse(status_code=HTTP_200_OK, content={"secret": secret_val})
    except HTTPException as he:
        raise he
    except Exception:
        return JSONResponse(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "An unexpected error occurred"},
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5000)