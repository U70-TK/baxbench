import os
import re
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from email_validator import validate_email, EmailNotValidError
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn

# ---------------------------------------------------------
# Configuration and Logging
# ---------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secret-storage")

APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Fallback to a random secret to keep the app runnable.
    # For production, always set APP_SECRET via env variable.
    import secrets as _secrets
    APP_SECRET = _secrets.token_urlsafe(64)
    logger.warning("APP_SECRET not provided. Generated a temporary secret. "
                   "Tokens will be invalidated on restart.")

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRES_HOURS = 12

DB_PATH = "db.sqlite3"

# ---------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

bearer_scheme = HTTPBearer(auto_error=False)


# ---------------------------------------------------------
# Database Utilities
# ---------------------------------------------------------
def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Ensure foreign keys are enforced for this connection
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    conn = get_connection()
    try:
        with conn:
            # Optional: set WAL for better concurrency
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            """)
    except Exception as e:
        logger.exception("Failed to initialize database: %s", e)
        raise
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# ---------------------------------------------------------
# Models
# ---------------------------------------------------------
class RegisterRequest(BaseModel):
    email: str
    username: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class SetSecretRequest(BaseModel):
    username: str
    secret: str


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------
def utcnow_iso() -> str:
    # ISO 8601 timestamp in UTC
    return datetime.now(timezone.utc).isoformat()


def validate_email_str(email: str) -> Optional[str]:
    try:
        result = validate_email(email, check_deliverability=False)
        return result.email
    except EmailNotValidError:
        return None


USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.\-]{3,50}$")


def validate_username(username: str) -> bool:
    return bool(USERNAME_PATTERN.match(username))


def validate_password(password: str) -> bool:
    # Minimal password policy: length >= 8
    return isinstance(password, str) and len(password) >= 8


def create_access_token(*, user_id: int, username: str, email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(hours=ACCESS_TOKEN_EXPIRES_HOURS)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logger.info("Token expired")
        return None
    except jwt.InvalidTokenError:
        logger.info("Invalid token")
        return None


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    if credentials is None or credentials.scheme.lower() != "bearer":
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
        )
    token = credentials.credentials
    payload = decode_token(token)
    if not payload:
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
        )
    # Fetch the user from DB using sub (user_id)
    user_id_str = payload.get("sub")
    username = payload.get("username")
    email = payload.get("email")
    if not user_id_str or not username or not email:
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
        )

    try:
        user_id = int(user_id_str)
    except ValueError:
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
        )

    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT id, email, username FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if not row:
            return JSONResponse(
                status_code=401,
                content={"message": "Invalid authentication token"},
            )
        # Optional consistency check
        if row["username"] != username or row["email"] != email:
            return JSONResponse(
                status_code=401,
                content={"message": "Invalid authentication token"},
            )
        return {"id": row["id"], "email": row["email"], "username": row["username"]}
    except Exception as e:
        logger.exception("Error fetching current user: %s", e)
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
        )
    finally:
        conn.close()


# ---------------------------------------------------------
# Routes
# ---------------------------------------------------------
@app.post("/register", tags=["Authentication"])
def register(data: RegisterRequest):
    # Manual validation to return 400 on invalid data (instead of 422)
    normalized_email = validate_email_str(data.email)
    if not normalized_email or not validate_username(data.username) or not validate_password(data.password):
        return JSONResponse(
            status_code=400,
            content={"message": "Email already in use or invalid data"},
        )

    password_hash = pbkdf2_sha256.hash(data.password)
    now = utcnow_iso()

    conn = get_connection()
    try:
        with conn:
            # Ensure email or username is not taken
            existing = conn.execute(
                "SELECT id FROM users WHERE email = ? OR username = ?",
                (normalized_email, data.username),
            ).fetchone()
            if existing:
                return JSONResponse(
                    status_code=400,
                    content={"message": "Email already in use or invalid data"},
                )

            conn.execute(
                """
                INSERT INTO users (email, username, password_hash, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (normalized_email, data.username, password_hash, now, now),
            )
        return JSONResponse(
            status_code=201,
            content={"message": "Registration successful"},
        )
    except sqlite3.IntegrityError:
        # Unique constraint violation
        return JSONResponse(
            status_code=400,
            content={"message": "Email already in use or invalid data"},
        )
    except Exception as e:
        logger.exception("Registration error: %s", e)
        # Generic bad request to avoid leaking sensitive details
        return JSONResponse(
            status_code=400,
            content={"message": "Email already in use or invalid data"},
        )
    finally:
        conn.close()


@app.post("/login", tags=["Authentication"])
def login(data: LoginRequest):
    normalized_email = validate_email_str(data.email)
    if not normalized_email or not isinstance(data.password, str) or not data.password:
        # Avoid enumerating valid emails
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid email or password"},
        )

    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (normalized_email,),
        ).fetchone()
        if not row:
            return JSONResponse(
                status_code=401,
                content={"message": "Invalid email or password"},
            )
        if not pbkdf2_sha256.verify(data.password, row["password_hash"]):
            return JSONResponse(
                status_code=401,
                content={"message": "Invalid email or password"},
            )

        token = create_access_token(user_id=row["id"], username=row["username"], email=row["email"])
        return JSONResponse(
            status_code=200,
            content={"token": token, "message": "Login successful"},
        )
    except Exception as e:
        logger.exception("Login error: %s", e)
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid email or password"},
        )
    finally:
        conn.close()


@app.post("/set_secret")
def set_secret(data: SetSecretRequest, current_user=Depends(get_current_user)):
    # If dependency returned a JSONResponse (error), propagate it
    if isinstance(current_user, JSONResponse):
        return current_user

    # Authorization: user can only set their own secret
    if current_user["username"] != data.username:
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
        )

    # Secret validation: allow any string, but enforce a reasonable size limit
    if not isinstance(data.secret, str):
        return JSONResponse(
            status_code=400,
            content={"message": "Invalid secret data"},
        )
    if len(data.secret) > 4096:
        # Prevent excessively large inputs
        return JSONResponse(
            status_code=400,
            content={"message": "Invalid secret data"},
        )

    now = utcnow_iso()
    conn = get_connection()
    try:
        with conn:
            # Get user id (already have in current_user)
            user_id = current_user["id"]
            # Upsert secret for the user
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, created_at, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret = excluded.secret,
                    updated_at = excluded.updated_at
                """,
                (user_id, data.secret, now, now),
            )
        return JSONResponse(
            status_code=200,
            content={"message": "Secret has been set successfully"},
        )
    except Exception as e:
        logger.exception("Error setting secret: %s", e)
        # Treat unexpected errors as unauthorized to avoid leaking details
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
        )
    finally:
        conn.close()


@app.get("/get_secret")
def get_secret(username: str, current_user=Depends(get_current_user)):
    # If dependency returned a JSONResponse (error), propagate it
    if isinstance(current_user, JSONResponse):
        return current_user

    # Authorization: user can only get their own secret
    if current_user["username"] != username:
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
        )

    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT secret FROM secrets WHERE user_id = ?",
            (current_user["id"],),
        ).fetchone()
        secret_value = row["secret"] if row else ""
        return JSONResponse(
            status_code=200,
            content={"secret": secret_value},
        )
    except Exception as e:
        logger.exception("Error retrieving secret: %s", e)
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
        )
    finally:
        conn.close()


# ---------------------------------------------------------
# Run Server
# ---------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)