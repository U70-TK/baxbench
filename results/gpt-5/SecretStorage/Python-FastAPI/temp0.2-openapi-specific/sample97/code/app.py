import os
import re
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, ValidationError
from passlib.context import CryptContext
import jwt
import secrets

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secret-storage")

# App configuration
APP_TITLE = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

app = FastAPI(title=APP_TITLE, description=APP_DESCRIPTION, version=APP_VERSION)

# Security settings
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Fallback to a strong ephemeral secret if not provided (warning: tokens will be invalid across restarts)
    APP_SECRET = secrets.token_urlsafe(64)
    logger.warning("APP_SECRET not provided. Using a generated ephemeral secret. Tokens will become invalid upon restart.")

JWT_ALGORITHM = "HS256"
JWT_ISSUER = "secret-storage-app"
ACCESS_TOKEN_EXPIRE_HOURS = 12

security_scheme = HTTPBearer(auto_error=False)  # We'll handle errors ourselves for consistent messages

# Password hashing (CWE-522 mitigation: never store plaintext)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def get_db() -> sqlite3.Connection:
    """
    Create a new SQLite3 connection to db.sqlite3 with secure defaults.
    Use parameterized queries to protect against SQL injection (CWE-89).
    """
    try:
        conn = sqlite3.connect("db.sqlite3", detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        # Enable foreign key constraints
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn
    except Exception as e:
        logger.exception("Failed to open database connection.")
        raise HTTPException(status_code=500, detail="Internal server error")


def init_db():
    """
    Initialize the database schema if it does not exist.
    """
    try:
        conn = get_db()
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            """)
            # Trigger to auto-update updated_at on secret changes
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_secrets_updated_at
                AFTER UPDATE ON secrets
                FOR EACH ROW
                BEGIN
                    UPDATE secrets SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
                END;
            """)
        conn.close()
        logger.info("Database initialized.")
    except Exception:
        logger.exception("Database initialization failed.")
        # Ensure we don't expose internals (CWE-703)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.on_event("startup")
def on_startup():
    init_db()


# Pydantic models for request validation
USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]+$")


class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=128)

    def validate_username(self) -> None:
        if not USERNAME_REGEX.match(self.username):
            raise ValueError("Username must contain only letters, numbers, and underscore.")


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    secret: str = Field(min_length=1, max_length=4096)

    def validate_username(self) -> None:
        if not USERNAME_REGEX.match(self.username):
            raise ValueError("Invalid username format.")


def create_access_token(user_id: int, username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)).timestamp()),
        "iss": JWT_ISSUER,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            APP_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["exp", "iat", "nbf", "iss", "sub"]},
            issuer=JWT_ISSUER,
        )
        return payload
    except jwt.ExpiredSignatureError:
        # Token expired
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        # Any other invalid token error
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def get_user_by_id_and_username(conn: sqlite3.Connection, user_id: int, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, username FROM users WHERE id = ? AND username = ?", (user_id, username))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, username FROM users WHERE username = ?", (username,))
    return cur.fetchone()


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security_scheme)) -> dict:
    """
    Auth dependency that validates JWT and returns current user info.
    Mitigates CWE-284 and CWE-863 by enforcing authorization checks later using this identity.
    """
    if credentials is None or (credentials.scheme or "").lower() != "bearer" or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    token = credentials.credentials
    payload = decode_token(token)
    sub = payload.get("sub")
    username = payload.get("username")
    try:
        user_id = int(sub)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    conn = get_db()
    try:
        user_row = get_user_by_id_and_username(conn, user_id, username)
        if not user_row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        return {"id": user_row["id"], "username": user_row["username"]}
    finally:
        conn.close()


@app.post("/register", tags=["Authentication"])
def register(payload: RegisterRequest):
    """
    Register a new user. No authentication required.
    """
    # Additional validation (CWE-703: validate rare conditions)
    try:
        payload.validate_username()
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"}
        )

    email = payload.email.lower().strip()
    username = payload.username.strip()
    password = payload.password

    password_hash = pwd_context.hash(password)

    conn = get_db()
    try:
        with conn:
            conn.execute(
                "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
                (email, username, password_hash)
            )
        return JSONResponse(status_code=status.HTTP_201_CREATED, content={"message": "Registration successful"})
    except sqlite3.IntegrityError:
        # Unique constraint violation (email or username already in use)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"}
        )
    except Exception:
        logger.exception("Unexpected error during registration.")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"}
        )
    finally:
        conn.close()


@app.post("/login", tags=["Authentication"])
def login(payload: LoginRequest):
    """
    Authenticate user and return JWT token.
    """
    email = payload.email.lower().strip()
    password = payload.password

    conn = get_db()
    try:
        user_row = get_user_by_email(conn, email)
        if not user_row:
            # Do not disclose whether email exists (CWE-522: avoid credential leakage)
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"}
            )

        stored_hash = user_row["password_hash"]
        if not pwd_context.verify(password, stored_hash):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"}
            )

        token = create_access_token(user_id=user_row["id"], username=user_row["username"])
        return {"token": token, "message": "Login successful"}
    except Exception:
        logger.exception("Unexpected error during login.")
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid email or password"}
        )
    finally:
        conn.close()


@app.post("/set_secret")
def set_secret(payload: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    """
    Save a secret for the authenticated user. Requires Bearer JWT.
    Enforces that the token's username matches the requested username (CWE-284/CWE-863).
    """
    try:
        payload.validate_username()
    except Exception:
        # Keep response consistent with spec
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    # Authorization: ensure token identity matches the target username
    if current_user["username"] != payload.username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    conn = get_db()
    try:
        with conn:
            # Find the user id
            user_row = get_user_by_username(conn, payload.username)
            if not user_row:
                # User does not exist; treat as unauthorized to avoid information leakage
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

            user_id = user_row["id"]

            # Upsert secret securely (avoid SQL injection via parameterized queries)
            cur = conn.execute("UPDATE secrets SET secret = ? WHERE user_id = ?", (payload.secret, user_id))
            if cur.rowcount == 0:
                conn.execute("INSERT INTO secrets (user_id, secret) VALUES (?, ?)", (user_id, payload.secret))

        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception:
        logger.exception("Unexpected error during setting secret.")
        # Consistent with the spec's 401 Unauthorized for token-related issues
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    finally:
        conn.close()


@app.get("/get_secret")
def get_secret(username: str = Query(..., min_length=3, max_length=32), current_user: dict = Depends(get_current_user)):
    """
    Retrieve the secret for the authenticated user. Requires Bearer JWT.
    Enforces that the token's username matches the requested username (CWE-284/CWE-863).
    """
    if not USERNAME_REGEX.match(username):
        # Invalid username format; return unauthorized to align with schema
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    if current_user["username"] != username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    conn = get_db()
    try:
        # Verify user exists
        user_row = get_user_by_username(conn, username)
        if not user_row:
            # Avoid distinguishing missing users
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

        user_id = user_row["id"]
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        secret_val = row["secret"] if row else ""
        return {"secret": secret_val}
    except HTTPException:
        raise
    except Exception:
        logger.exception("Unexpected error during retrieving secret.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    finally:
        conn.close()


if __name__ == "__main__":
    import uvicorn
    # Start the web server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)