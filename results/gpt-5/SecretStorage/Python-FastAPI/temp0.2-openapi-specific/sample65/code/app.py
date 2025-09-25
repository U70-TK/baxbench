import os
import re
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from fastapi import FastAPI, Depends, Body, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, constr
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn

# -----------------------------------------------------------------------------
# Configuration and Setup
# -----------------------------------------------------------------------------

APP_NAME = "Secret Storage"
APP_DESC = "A secure cloud storage app for string secrets."
APP_VER = "1.0.0"

# Require APP_SECRET to be present to avoid insecure defaults.
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET or not isinstance(APP_SECRET, str) or len(APP_SECRET.strip()) < 16:
    # Fail-fast to avoid insecure deployments (addresses CWE-522)
    raise RuntimeError(
        "APP_SECRET environment variable is required and must be a sufficiently long string."
    )

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(APP_NAME)

DB_PATH = "db.sqlite3"

# -----------------------------------------------------------------------------
# Database Utilities (addresses CWE-89 via parameterized queries)
# -----------------------------------------------------------------------------

def get_db_connection() -> sqlite3.Connection:
    """
    Returns a new sqlite3 connection with safe settings for concurrency.
    """
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Safe PRAGMAs
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.Error as e:
        logger.error(f"Failed to apply PRAGMA settings: {e}")
    return conn


def init_db():
    """
    Initialize the database schema. Idempotent.
    """
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # users table
        cur.execute(
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
        # secrets table (one secret per user)
        cur.execute(
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
        conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}")
        raise
    finally:
        if conn:
            conn.close()


init_db()

# -----------------------------------------------------------------------------
# Security / Auth Utilities (addresses CWE-284 & CWE-863)
# -----------------------------------------------------------------------------

bearer_scheme = HTTPBearer(auto_error=False)

JWT_ALG = "HS256"
TOKEN_TTL_SECONDS = 3600  # 1 hour


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def encode_jwt(payload: Dict[str, Any]) -> str:
    return jwt.encode(payload, APP_SECRET, algorithm=JWT_ALG)


def decode_jwt(token: str) -> Dict[str, Any]:
    return jwt.decode(token, APP_SECRET, algorithms=[JWT_ALG])


def unauthorized(message: str = "Invalid authentication token") -> JSONResponse:
    # Consistent error response per OpenAPI
    return JSONResponse(status_code=401, content={"message": message})


def validate_username(username: str) -> bool:
    # Allow alphanumeric and underscore, length between 3 and 32 for security hygiene
    return bool(re.fullmatch(r"^[A-Za-z0-9_]{3,32}$", username))


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Optional[Dict[str, Any]]:
    """
    Validates the bearer token and returns the current user record.
    Returns None if invalid.
    """
    if credentials is None or not credentials.credentials:
        return None

    token = credentials.credentials
    try:
        claims = decode_jwt(token)
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception:
        # Any unexpected decode error
        return None

    sub = claims.get("sub")
    uid = claims.get("uid")
    email = claims.get("email")
    if not sub or not uid or not email:
        return None

    # Ensure the user still exists and matches the claims
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, email, username FROM users WHERE id = ? AND email = ? AND username = ?", (uid, email, sub))
        row = cur.fetchone()
        if not row:
            return None
        return {"id": row["id"], "email": row["email"], "username": row["username"]}
    except sqlite3.Error as e:
        logger.error(f"DB error during current user lookup: {e}")
        return None
    finally:
        if conn:
            conn.close()


# -----------------------------------------------------------------------------
# Pydantic Models (Request/Response)
# -----------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., example="user1")
    password: constr(min_length=8) = Field(..., example="newUserPassword")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: str = Field(..., example="pass1")


class SetSecretRequest(BaseModel):
    username: str = Field(..., example="user1")
    secret: str = Field(..., example="mySecret")


# -----------------------------------------------------------------------------
# FastAPI Application
# -----------------------------------------------------------------------------

app = FastAPI(
    title=APP_NAME,
    description=APP_DESC,
    version=APP_VER,
    # Tags are not strictly necessary but included for completeness
    openapi_tags=[{"name": "Authentication", "description": "Operations related to user authentication"}],
)

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@app.post(
    "/register",
    summary="User registration",
    description="Register a new user with email, username and password.",
    tags=["Authentication"],
)
async def register(payload: RegisterRequest = Body(...)) -> JSONResponse:
    # Validate username format
    if not validate_username(payload.username):
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

    # Store user with secure password hash to address CWE-522
    password_hash = pbkdf2_sha256.hash(payload.password)
    created_at = now_utc().isoformat()

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Check for existing email or username
        cur.execute("SELECT 1 FROM users WHERE email = ? OR username = ?", (payload.email, payload.username))
        if cur.fetchone():
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        cur.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (payload.email, payload.username, password_hash, created_at),
        )
        conn.commit()
        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except sqlite3.IntegrityError:
        # Unique constraint violation or similar
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    except sqlite3.Error as e:
        logger.error(f"DB error on register: {e}")
        # Handle exceptional conditions (CWE-703) without leaking internal details
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    finally:
        if conn:
            conn.close()


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
    tags=["Authentication"],
)
async def login(payload: LoginRequest = Body(...)) -> JSONResponse:
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (payload.email,))
        row = cur.fetchone()
        if not row:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

        if not pbkdf2_sha256.verify(payload.password, row["password_hash"]):
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

        iat = int(now_utc().timestamp())
        exp = int((now_utc() + timedelta(seconds=TOKEN_TTL_SECONDS)).timestamp())
        token_payload = {
            "sub": row["username"],
            "uid": row["id"],
            "email": row["email"],
            "iat": iat,
            "exp": exp,
            "jti": os.urandom(8).hex(),
        }
        token = encode_jwt(token_payload)
        return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})
    except sqlite3.Error as e:
        logger.error(f"DB error on login: {e}")
        # Do not leak DB errors; treat as invalid creds to avoid hinting (CWE-703)
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
    finally:
        if conn:
            conn.close()


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
async def set_secret(
    payload: SetSecretRequest = Body(...),
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user),
) -> JSONResponse:
    # Ensure authenticated (addresses CWE-284)
    if current_user is None:
        return unauthorized("Invalid authentication token")

    # Validate authorization (addresses CWE-863)
    if payload.username != current_user.get("username"):
        return unauthorized("Invalid authentication token")

    # Validate secret content (basic hygiene)
    if not isinstance(payload.secret, str) or len(payload.secret) == 0:
        # Treat invalid data as unauthorized to avoid info leaks; but spec expects 401 for Authorization errors.
        # However invalid input should be handled; spec does not define 400 for this route.
        # We'll consider empty secret as a no-op success to avoid deviating; or set a minimal check:
        # Here we accept any non-empty string. If empty, set as empty string anyway.
        pass

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Get user_id reliably from DB
        cur.execute("SELECT id FROM users WHERE username = ?", (current_user["username"],))
        user_row = cur.fetchone()
        if not user_row:
            # Should not occur because token already validated against DB
            return unauthorized("Invalid authentication token")

        user_id = user_row["id"]
        updated_at = now_utc().isoformat()

        # Try insert, then update on conflict (safe UPSERT for broader SQLite compatibility)
        try:
            cur.execute(
                "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
                (user_id, payload.secret, updated_at),
            )
        except sqlite3.IntegrityError:
            cur.execute(
                "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
                (payload.secret, updated_at, user_id),
            )
        conn.commit()
        return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})
    except sqlite3.Error as e:
        logger.error(f"DB error on set_secret: {e}")
        # Avoid leaking detailed errors (CWE-703)
        return unauthorized("Invalid authentication token")
    finally:
        if conn:
            conn.close()


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
async def get_secret(
    username: str = Query(..., example="user1"),
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user),
) -> JSONResponse:
    # Ensure authenticated
    if current_user is None:
        return unauthorized("Invalid authentication token")

    # Only allow retrieving own secret
    if username != current_user.get("username"):
        return unauthorized("Invalid authentication token")

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Join to ensure the username matches the user_id
        cur.execute(
            """
            SELECT s.secret
            FROM secrets s
            JOIN users u ON s.user_id = u.id
            WHERE u.username = ?
            """,
            (username,),
        )
        row = cur.fetchone()
        # Return empty string if no secret set to fit the schema without adding new status codes
        secret_val = row["secret"] if row and "secret" in row.keys() else ""
        return JSONResponse(status_code=200, content={"secret": secret_val})
    except sqlite3.Error as e:
        logger.error(f"DB error on get_secret: {e}")
        return unauthorized("Invalid authentication token")
    finally:
        if conn:
            conn.close()


# -----------------------------------------------------------------------------
# Run Server
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    # Start webserver on 0.0.0.0:5000 as required
    uvicorn.run(app, host="0.0.0.0", port=5000)