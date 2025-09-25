import os
import sqlite3
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Request, Query
from fastapi import status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s"
)
logger = logging.getLogger("secret-storage")

# Read application secret
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Generate a strong random secret if none provided. This is ephemeral and not persisted.
    APP_SECRET = secrets.token_urlsafe(64)
    logger.warning("APP_SECRET environment variable not set. Generated an ephemeral secret for this run.")

JWT_ALGORITHM = "HS256"
JWT_ISSUER = "secret-storage-app"
TOKEN_TTL_MINUTES = 60

DB_PATH = "db.sqlite3"


def get_db_connection() -> sqlite3.Connection:
    """
    Create and return a new SQLite connection.
    Using a new connection per request helps avoid threading issues.
    """
    conn = sqlite3.connect(DB_PATH, timeout=10.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    # Defensive pragmas for reliability
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except Exception as e:
        logger.error("Failed to set SQLite pragmas: %s", e)
    return conn


def init_db():
    """
    Initialize database schema.
    """
    try:
        conn = get_db_connection()
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            """)
        conn.close()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.exception("Database initialization failed: %s", e)
        raise


def create_jwt_for_user(username: str) -> str:
    now = datetime.now(tz=timezone.utc)
    payload = {
        "iss": JWT_ISSUER,
        "sub": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=TOKEN_TTL_MINUTES)).timestamp())
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_and_validate_token(token: Optional[str]) -> Optional[dict]:
    """
    Decode JWT token and validate claims. Return payload if valid, else None.
    """
    if not token:
        return None
    try:
        payload = jwt.decode(
            token,
            APP_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["sub", "exp", "iat", "iss"]},
        )
        if payload.get("iss") != JWT_ISSUER:
            return None
        # Additional checks could be added (e.g., jti, aud), but not strictly needed here.
        return payload
    except jwt.ExpiredSignatureError:
        logger.info("Expired token")
        return None
    except jwt.InvalidTokenError as e:
        logger.info("Invalid token: %s", e)
        return None
    except Exception as e:
        logger.error("Unexpected token decode error: %s", e)
        return None


# Pydantic models

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(
        ...,
        min_length=3,
        max_length=32,
        pattern=r"^[A-Za-z0-9_]+$",
        examples=["user1"]
    )
    password: str = Field(..., min_length=8, max_length=128, examples=["newUserPassword"])


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user@example.com"])
    password: str = Field(..., min_length=8, max_length=128, examples=["mySecretPassword"])


class SetSecretRequest(BaseModel):
    username: str = Field(
        ...,
        min_length=3,
        max_length=32,
        pattern=r"^[A-Za-z0-9_]+$",
        examples=["user1"]
    )
    secret: str = Field(..., min_length=1, max_length=4096, examples=["mySecret"])


# FastAPI application
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    openapi_tags=[{"name": "Authentication", "description": "Operations related to user authentication"}],
)


@app.on_event("startup")
def on_startup():
    try:
        init_db()
    except Exception:
        # If DB init fails, the app shouldn't run incorrectly; log and re-raise.
        logger.critical("Failed to initialize DB on startup. Exiting.")
        raise


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT * FROM users WHERE email = ?;", (email,))
        return cur.fetchone()
    except Exception as e:
        logger.error("Error fetching user by email: %s", e)
        return None


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT * FROM users WHERE username = ?;", (username,))
        return cur.fetchone()
    except Exception as e:
        logger.error("Error fetching user by username: %s", e)
        return None


def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> bool:
    try:
        now = datetime.now(tz=timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (email, username, password_hash, now)
        )
        return True
    except sqlite3.IntegrityError:
        # Unique constraint violation
        return False
    except Exception as e:
        logger.error("Error creating user: %s", e)
        return False


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> bool:
    try:
        now = datetime.now(tz=timezone.utc).isoformat()
        # Try update first
        cur = conn.execute(
            "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?;",
            (secret, now, user_id)
        )
        if cur.rowcount == 0:
            # No existing secret, insert new
            conn.execute(
                "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?);",
                (user_id, secret, now)
            )
        return True
    except Exception as e:
        logger.error("Error upserting secret: %s", e)
        return False


def get_secret(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        if not row:
            return None
        return row["secret"]
    except Exception as e:
        logger.error("Error retrieving secret: %s", e)
        return None


@app.post("/register", tags=["Authentication"])
async def register(req: RegisterRequest):
    conn = get_db_connection()
    try:
        # Validate uniqueness
        existing_email = get_user_by_email(conn, req.email)
        existing_username = get_user_by_username(conn, req.username)
        if existing_email or existing_username:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )

        # Hash password securely
        try:
            password_hash = pbkdf2_sha256.hash(req.password)
        except Exception as e:
            logger.error("Password hashing failed: %s", e)
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )

        ok = create_user(conn, req.email, req.username, password_hash)
        if not ok:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )

        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"message": "Registration successful"},
        )
    except Exception as e:
        logger.error("Unexpected error during registration: %s", e)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.post("/login", tags=["Authentication"])
async def login(req: LoginRequest):
    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, req.email)
        if not user:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
            )
        password_hash = user["password_hash"]
        try:
            if not pbkdf2_sha256.verify(req.password, password_hash):
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"message": "Invalid email or password"},
                )
        except Exception as e:
            logger.error("Password verification error: %s", e)
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
            )

        token = create_jwt_for_user(user["username"])
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"token": token, "message": "Login successful"},
        )
    except Exception as e:
        logger.error("Unexpected error during login: %s", e)
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid email or password"},
        )
    finally:
        try:
            conn.close()
        except Exception:
            pass


def extract_bearer_token(request: Request) -> Optional[str]:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not isinstance(auth_header, str):
        return None
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1]


@app.post("/set_secret")
async def set_secret(request: Request, body: SetSecretRequest):
    # Authenticate using Bearer token
    token = extract_bearer_token(request)
    payload = decode_and_validate_token(token)
    if not payload:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )

    # Authorization: ensure token subject matches provided username
    token_username = payload.get("sub")
    if token_username != body.username:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, body.username)
        if not user:
            # Avoid user enumeration, treat as invalid token/unauthorized
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid authentication token"},
            )

        ok = upsert_secret(conn, user["id"], body.secret)
        if not ok:
            # Don't leak details
            logger.error("Failed to set secret for user_id=%s", user["id"])
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid authentication token"},
            )

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "Secret has been set successfully"},
        )
    except Exception as e:
        logger.error("Unexpected error while setting secret: %s", e)
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.get("/get_secret")
async def get_secret_endpoint(request: Request, username: str = Query(..., examples=["user1"])):
    # Authenticate using Bearer token
    token = extract_bearer_token(request)
    payload = decode_and_validate_token(token)
    if not payload:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )

    # Authorization: ensure token subject matches provided username
    token_username = payload.get("sub")
    if token_username != username:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, username)
        if not user:
            # Avoid user enumeration; treat as unauthorized.
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid authentication token"},
            )

        s = get_secret(conn, user["id"])
        # If no secret, return empty string to avoid unnecessary information leakage.
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"secret": s if s is not None else ""},
        )
    except Exception as e:
        logger.error("Unexpected error while retrieving secret: %s", e)
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )
    finally:
        try:
            conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)