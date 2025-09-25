import os
import re
import base64
import hashlib
import hmac
import secrets as pysecrets
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, ValidationError
from email_validator import validate_email, EmailNotValidError
import jwt
import uvicorn

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secret-storage")

# Application constants and security configuration
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate a random secret if not provided; warn in logs
    APP_SECRET = base64.urlsafe_b64encode(pysecrets.token_bytes(32)).decode("ascii")
    logger.warning("APP_SECRET not provided. Generated a temporary secret. "
                   "Use a stable secret in production via APP_SECRET env variable.")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Database configuration
DB_PATH = "db.sqlite3"

# FastAPI app metadata that corresponds to the given OpenAPI info block
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

bearer_scheme = HTTPBearer(auto_error=False)


# Pydantic request models for validation
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., examples=["user1"])
    password: str = Field(..., min_length=8, examples=["newUserPassword"])


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user1@example.com"])
    password: str = Field(..., min_length=8, examples=["pass1"])


class SetSecretRequest(BaseModel):
    username: str = Field(..., examples=["user1"])
    secret: str = Field(..., min_length=1, max_length=4096, examples=["mySecret"])


# Utility functions for secure password hashing and verification
def _hash_password(password: str) -> str:
    """
    Securely hash a password using PBKDF2-HMAC-SHA256 with a random salt.
    Format: pbkdf2_sha256$iterations$salt_b64$hash_b64
    """
    iterations = 200_000
    salt = pysecrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode('ascii')}${base64.b64encode(dk).decode('ascii')}"


def _verify_password(password: str, stored_hash: str) -> bool:
    try:
        alg, iter_str, salt_b64, hash_b64 = stored_hash.split("$")
        if alg != "pbkdf2_sha256":
            return False
        iterations = int(iter_str)
        salt = base64.b64decode(salt_b64.encode("ascii"))
        expected = base64.b64decode(hash_b64.encode("ascii"))
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=len(expected))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


# Database helpers
def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30.0, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Apply safe pragmas
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.Error as e:
        logger.error(f"SQLite PRAGMA error: {e}")
    return conn


def init_db() -> None:
    conn = get_db_connection()
    try:
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
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
    except sqlite3.Error as e:
        logger.error(f"Failed to initialize database: {e}")
        raise
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    # Initialize DB at startup
    try:
        init_db()
    except Exception as e:
        # If DB init fails, crash early to avoid undefined behavior (CWE-703)
        logger.critical(f"Application startup failed due to DB init error: {e}")
        raise


# User data access functions
def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[Dict[str, Any]]:
    try:
        cur = conn.execute("SELECT * FROM users WHERE email = ?;", (email,))
        row = cur.fetchone()
        return dict(row) if row else None
    except sqlite3.Error as e:
        logger.error(f"DB error in get_user_by_email: {e}")
        raise


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[Dict[str, Any]]:
    try:
        cur = conn.execute("SELECT * FROM users WHERE username = ?;", (username,))
        row = cur.fetchone()
        return dict(row) if row else None
    except sqlite3.Error as e:
        logger.error(f"DB error in get_user_by_username: {e}")
        raise


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[Dict[str, Any]]:
    try:
        cur = conn.execute("SELECT * FROM users WHERE id = ?;", (user_id,))
        row = cur.fetchone()
        return dict(row) if row else None
    except sqlite3.Error as e:
        logger.error(f"DB error in get_user_by_id: {e}")
        raise


def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> None:
    try:
        created_at = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (email.lower(), username, password_hash, created_at),
        )
    except sqlite3.IntegrityError:
        # Duplicate email or username
        raise
    except sqlite3.Error as e:
        logger.error(f"DB error in create_user: {e}")
        raise


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    try:
        updated_at = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET secret = excluded.secret, updated_at = excluded.updated_at;
            """,
            (user_id, secret, updated_at),
        )
    except sqlite3.Error as e:
        logger.error(f"DB error in upsert_secret: {e}")
        raise


def get_secret_by_user_id(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        return row["secret"] if row else None
    except sqlite3.Error as e:
        logger.error(f"DB error in get_secret_by_user_id: {e}")
        raise


# JWT helpers
def create_access_token(user_id: int, username: str, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
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
            detail={"message": "Invalid authentication token"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )


# Authorization dependency
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    request: Request = None,
) -> Dict[str, Any]:
    if credentials is None or not credentials.scheme.lower() == "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    token = credentials.credentials
    payload = decode_token(token)
    user_id_str = payload.get("sub")
    username_claim = payload.get("username")
    if not user_id_str or not username_claim:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    try:
        user_id = int(user_id_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    conn = get_db_connection()
    try:
        user = get_user_by_id(conn, user_id)
        if not user or user["username"] != username_claim:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        return user
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )
    finally:
        conn.close()


# Validators
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def validate_username(username: str) -> bool:
    return USERNAME_PATTERN.fullmatch(username) is not None


# Routes corresponding to the OpenAPI schema

@app.post(
    "/register",
    summary="User registration",
    description="Register a new user with email, username and password.",
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
)
def register(payload: RegisterRequest):
    # Validate email strictly
    try:
        validate_email(payload.email, check_deliverability=False)
    except EmailNotValidError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    # Validate username
    if not validate_username(payload.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    # Validate password
    if len(payload.password) < 8 or len(payload.password) > 128:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )

    password_hash = _hash_password(payload.password)
    conn = get_db_connection()
    try:
        # Check duplicates explicitly to provide proper error messages
        if get_user_by_email(conn, payload.email.lower()) is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )
        if get_user_by_username(conn, payload.username) is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )
        create_user(conn, payload.email.lower(), payload.username, password_hash)
        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except sqlite3.IntegrityError:
        # Race: unique constraint violation
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )
    finally:
        conn.close()


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
    tags=["Authentication"],
)
def login(payload: LoginRequest):
    # Validate email strictly
    try:
        validate_email(payload.email, check_deliverability=False)
    except EmailNotValidError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"},
        )
    if len(payload.password) < 8 or len(payload.password) > 128:
        # For security, return generic message
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"},
        )

    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, payload.email.lower())
        if not user or not _verify_password(payload.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )
        token = create_access_token(user_id=int(user["id"]), username=user["username"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )
    finally:
        conn.close()


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(payload: SetSecretRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    # Authorization check: ensure the token belongs to the same username (CWE-863/CWE-284)
    if payload.username != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    secret_text = payload.secret
    if not isinstance(secret_text, str) or len(secret_text) == 0 or len(secret_text) > 4096:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Invalid secret data"},
        )
    conn = get_db_connection()
    try:
        upsert_secret(conn, int(current_user["id"]), secret_text)
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )
    finally:
        conn.close()


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(username: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    # Authorization check: ensure the token belongs to the same username
    if username != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    conn = get_db_connection()
    try:
        secret_value = get_secret_by_user_id(conn, int(current_user["id"]))
        if secret_value is None:
            # If no secret set, return empty string to avoid leaking existence details
            secret_value = ""
        return {"secret": secret_value}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )
    finally:
        conn.close()


# Run the server
if __name__ == "__main__":
    # Ensure DB is initialized before serving
    try:
        init_db()
    except Exception as e:
        logger.critical(f"Failed to initialize DB before starting server: {e}")
        raise
    uvicorn.run(app, host="0.0.0.0", port=5000)