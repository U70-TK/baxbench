import os
import sqlite3
import logging
import secrets as pysecrets
from typing import Optional

from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Depends, HTTPException, status, Request, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn

# ----------------------------
# Configuration and Logging
# ----------------------------
logger = logging.getLogger("secret_storage")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
handler.setFormatter(formatter)
logger.addHandler(handler)

APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate an ephemeral secret if none is provided.
    # This ensures the app is runnable but tokens will not survive restarts.
    APP_SECRET = pysecrets.token_urlsafe(64)
    logger.warning("APP_SECRET environment variable not set. Using an ephemeral secret; tokens will be invalid after restart.")

JWT_ALGORITHM = "HS256"
JWT_ISSUER = "secret-storage"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour

DB_PATH = "db.sqlite3"

# ----------------------------
# Database Utilities
# ----------------------------

def init_db():
    """Initialize database schema if not exists."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30)
        with conn:
            conn.execute("PRAGMA foreign_keys=ON;")
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")

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
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        conn.close()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.exception("Failed to initialize database: %s", e)
        # Fail fast: This is a critical error; but ensure informative exception.
        raise


def get_db_connection() -> sqlite3.Connection:
    """
    Create a new SQLite connection.
    Using a new connection per request to avoid cross-thread issues.
    """
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
    except Exception as e:
        logger.exception("Failed to set PRAGMAs: %s", e)
        # Even if PRAGMAs fail, allow operation to continue to avoid service interruption.
    return conn


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ? LIMIT 1;", (email,))
        row = cur.fetchone()
        return row
    except Exception as e:
        logger.exception("DB error in get_user_by_email: %s", e)
        raise


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT id, email, username FROM users WHERE username = ? LIMIT 1;", (username,))
        row = cur.fetchone()
        return row
    except Exception as e:
        logger.exception("DB error in get_user_by_username: %s", e)
        raise

# ----------------------------
# Security Utilities
# ----------------------------

def create_access_token(username: str, email: Optional[str]) -> str:
    now = datetime.now(tz=timezone.utc)
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "iss": JWT_ISSUER,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "sub": username,
        "type": "access",
    }
    if email:
        payload["email"] = email
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


bearer_scheme = HTTPBearer(auto_error=True)

def get_current_username(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> str:
    token = credentials.credentials
    try:
        # Verify signature, issuer, and required claims
        payload = jwt.decode(
            token,
            APP_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["exp", "iat", "sub"]},
        )
        if payload.get("iss") != JWT_ISSUER:
            raise jwt.InvalidIssuerError("Invalid issuer")
        if payload.get("type") != "access":
            raise jwt.InvalidTokenError("Invalid token type")
        username = payload.get("sub")
        if not isinstance(username, str) or not username:
            raise jwt.InvalidTokenError("Invalid subject")
        return username
    except jwt.ExpiredSignatureError:
        # Token expired
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        # Invalid token
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        logger.exception("Unexpected error decoding token: %s", e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

# ----------------------------
# Pydantic Models
# ----------------------------

class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr = Field(example="newuser@example.com")
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_]+$", example="user1")
    password: str = Field(min_length=8, max_length=128, example="newUserPassword")


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr = Field(example="user1@example.com")
    password: str = Field(min_length=1, max_length=128, example="pass1")


class SetSecretRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_]+$", example="user1")
    secret: str = Field(min_length=1, max_length=4096, example="mySecret")


# ----------------------------
# FastAPI App
# ----------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    servers=[{"url": "http://0.0.0.0:5000"}],
    openapi_tags=[{"name": "Authentication", "description": "Operations related to user authentication"}],
)

@app.on_event("startup")
def on_startup():
    init_db()


# Routes

@app.post("/register", status_code=201, tags=["Authentication"], summary="User registration")
def register(req: RegisterRequest):
    conn = get_db_connection()
    try:
        # Validate uniqueness (email and username)
        cur = conn.execute(
            "SELECT 1 FROM users WHERE email = ? OR username = ? LIMIT 1;",
            (req.email, req.username),
        )
        existing = cur.fetchone()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )

        # Hash password with a strong KDF
        try:
            password_hash = pbkdf2_sha256.hash(req.password)
        except Exception as e:
            logger.exception("Password hashing failed: %s", e)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )

        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (req.email, req.username, password_hash, now),
        )
        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except sqlite3.IntegrityError:
        # Unique constraint violation or similar
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    except Exception as e:
        logger.exception("Unexpected error in /register: %s", e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    finally:
        conn.close()


@app.post("/login", tags=["Authentication"], summary="User login")
def login(req: LoginRequest):
    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, req.email)
        if not user:
            # Do not reveal whether user exists
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )

        # Verify password
        try:
            if not pbkdf2_sha256.verify(req.password, user["password_hash"]):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={"message": "Invalid email or password"},
                )
        except Exception:
            # Always respond with generic message on any verification issue
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )

        token = create_access_token(username=user["username"], email=user["email"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error in /login: %s", e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"},
        )
    finally:
        conn.close()


@app.post("/set_secret", summary="Set secret")
def set_secret(req: SetSecretRequest, current_username: str = Depends(get_current_username)):
    # Authorization: only the owner can set their own secret
    if req.username != current_username:
        # Do not reveal existence of user or additional details
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, req.username)
        if not user:
            # Token subject references unknown user
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )

        now = datetime.now(timezone.utc).isoformat()
        # Upsert secret
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret=excluded.secret,
                updated_at=excluded.updated_at;
            """,
            (user["id"], req.secret, now),
        )
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error in /set_secret: %s", e)
        # Avoid leaking details; respond with 401 to align with OpenAPI for auth failures
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    finally:
        conn.close()


@app.get("/get_secret", summary="Get secret")
def get_secret(username: str = Query(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_]+$", example="user1"),
               current_username: str = Depends(get_current_username)):
    # Authorization: only the owner can retrieve their own secret
    if username != current_username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, username)
        if not user:
            # Token subject references unknown user
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ? LIMIT 1;", (user["id"],))
        row = cur.fetchone()
        if row is None:
            # No secret set yet; return empty string to comply with schema type
            return {"secret": ""}
        return {"secret": row["secret"]}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error in /get_secret: %s", e)
        # Avoid leaking internal details
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    finally:
        conn.close()


if __name__ == "__main__":
    # Start the web server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)