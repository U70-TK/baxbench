import os
import sqlite3
import logging
import secrets as sys_secrets
from datetime import datetime, timedelta
from typing import Optional

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Security, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, constr
from passlib.context import CryptContext
import jwt

# ------------------------------------------------------------------------------
# Configuration & Security
# ------------------------------------------------------------------------------

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("secret-storage")

# Application secret for JWT signing
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to a random secret to keep the app running; tokens won't persist across restarts.
    APP_SECRET = sys_secrets.token_urlsafe(64)
    logger.warning("APP_SECRET env var not set. Using a generated ephemeral secret.")

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour

# Password hashing context
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# Bearer auth scheme for FastAPI documentation and dependency
bearer_scheme = HTTPBearer(auto_error=False)

# ------------------------------------------------------------------------------
# Database Utilities
# ------------------------------------------------------------------------------

DB_NAME = "db.sqlite3"


def get_db_connection() -> sqlite3.Connection:
    """
    Create a new SQLite connection per operation to avoid cross-thread issues.
    Ensure foreign keys are enabled.
    """
    conn = sqlite3.connect(DB_NAME, timeout=30, isolation_level=None)  # autocommit mode
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.Error as e:
        logger.error(f"SQLite PRAGMA setup failed: {e}")
    return conn


def init_db() -> None:
    """
    Initialize database tables if they do not exist.
    """
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
                    created_at TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    secret_text TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
        conn.close()
        logger.info("Database initialized.")
    except sqlite3.Error as e:
        logger.exception(f"Failed to initialize database: {e}")
        raise


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    """
    Fetch user by email.
    """
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ? LIMIT 1", (email,))
        row = cur.fetchone()
        return row
    except sqlite3.Error as e:
        logger.error(f"Database error in get_user_by_email: {e}")
        return None
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    """
    Fetch user by username.
    """
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ? LIMIT 1", (username,))
        row = cur.fetchone()
        return row
    except sqlite3.Error as e:
        logger.error(f"Database error in get_user_by_username: {e}")
        return None
    finally:
        conn.close()


def set_user_secret(user_id: int, secret_text: str) -> bool:
    """
    Upsert the user's secret text using a unique constraint on user_id.
    """
    conn = get_db_connection()
    try:
        now = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret_text, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret_text=excluded.secret_text,
                updated_at=excluded.updated_at;
            """,
            (user_id, secret_text, now),
        )
        return True
    except sqlite3.Error as e:
        logger.error(f"Database error in set_user_secret: {e}")
        return False
    finally:
        conn.close()


def get_user_secret(user_id: int) -> Optional[str]:
    """
    Retrieve a user's secret text.
    """
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT secret_text FROM secrets WHERE user_id = ? LIMIT 1", (user_id,))
        row = cur.fetchone()
        if row:
            return row["secret_text"]
        return None
    except sqlite3.Error as e:
        logger.error(f"Database error in get_user_secret: {e}")
        return None
    finally:
        conn.close()


# ------------------------------------------------------------------------------
# Schemas
# ------------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    username: constr(pattern=r"^[a-zA-Z0-9_]{3,32}$")
    password: constr(min_length=8, max_length=128)


class RegisterResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=8, max_length=128)


class LoginResponse(BaseModel):
    token: str
    message: str


class SetSecretRequest(BaseModel):
    username: constr(pattern=r"^[a-zA-Z0-9_]{3,32}$")
    secret: constr(min_length=1, max_length=8192)


class MessageResponse(BaseModel):
    message: str


class GetSecretResponse(BaseModel):
    secret: str


# ------------------------------------------------------------------------------
# Auth Utilities
# ------------------------------------------------------------------------------

def create_access_token(username: str, email: str, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token with expiration.
    """
    to_encode = {
        "sub": username,
        "email": email,
        "iat": int(datetime.utcnow().timestamp()),
    }
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def get_current_token_claims(credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)) -> dict:
    """
    Validate and decode the JWT from the Authorization header.
    """
    if credentials is None or not credentials.scheme.lower() == "bearer" or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    token = credentials.credentials
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


# ------------------------------------------------------------------------------
# FastAPI Application
# ------------------------------------------------------------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Initialize database on startup
@app.on_event("startup")
def on_startup():
    try:
        init_db()
    except Exception as e:
        logger.exception(f"Startup initialization failed: {e}")
        # In case of DB init failure, we keep app up but any DB call will fail gracefully.


# ------------------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------------------

@app.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED, tags=["Authentication"])
def register_user(body: RegisterRequest):
    """
    Register a new user with email, username, and password.
    """
    # Hash the password securely (CWE-522 mitigation)
    try:
        password_hash = pwd_context.hash(body.password)
    except Exception as e:
        logger.error(f"Password hashing failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )

    try:
        conn = get_db_connection()
        now = datetime.utcnow().isoformat() + "Z"
        with conn:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (body.email, body.username, password_hash, now),
            )
        conn.close()
    except sqlite3.IntegrityError:
        # Handle duplicate email/username without revealing which one (CWE-703 thoughtful handling)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    except sqlite3.Error as e:
        logger.error(f"Database error during registration: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )

    return {"message": "Registration successful"}


@app.post("/login", response_model=LoginResponse, tags=["Authentication"])
def login_user(body: LoginRequest):
    """
    Authenticate a user with email and password.
    """
    user = get_user_by_email(body.email)
    if not user:
        # Do not reveal whether the email exists (CWE-284/CWE-863 related: avoid info disclosure)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"},
        )

    try:
        if not pwd_context.verify(body.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )
    except Exception:
        # Any error during verification is treated as auth failure to prevent leaking details
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"},
        )

    token = create_access_token(username=user["username"], email=user["email"])
    return {"token": token, "message": "Login successful"}


@app.post("/set_secret", response_model=MessageResponse)
def set_secret(body: SetSecretRequest, claims: dict = Depends(get_current_token_claims)):
    """
    Save a secret on the server using the username (must match token subject) and the secret text.
    Authorization: Bearer <token>
    """
    # Authorization (CWE-284/CWE-863 mitigation): ensure token subject matches the requested username
    token_username = claims.get("sub", "")
    if token_username != body.username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    # Ensure the user exists
    user = get_user_by_username(body.username)
    if not user:
        # Do not reveal existence details; treat as invalid token context
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    # Save the secret securely using parameterized queries (CWE-89 mitigation)
    success = set_user_secret(user_id=user["id"], secret_text=body.secret)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )

    return {"message": "Secret has been set successfully"}


@app.get("/get_secret", response_model=GetSecretResponse)
def get_secret(username: constr(pattern=r"^[a-zA-Z0-9_]{3,32}$") = Query(...), claims: dict = Depends(get_current_token_claims)):
    """
    Retrieve a secret based on the provided username.
    Authorization: Bearer <token>
    """
    token_username = claims.get("sub", "")
    if token_username != username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    user = get_user_by_username(username)
    if not user:
        # Avoid user enumeration
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    secret_text = get_user_secret(user_id=user["id"])
    if secret_text is None:
        # If no secret is set yet, return empty string to avoid information leakage
        return {"secret": ""}

    return {"secret": secret_text}


# ------------------------------------------------------------------------------
# Run Server
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000 without auto-reload (production-like)
    uvicorn.run(app, host="0.0.0.0", port=5000)