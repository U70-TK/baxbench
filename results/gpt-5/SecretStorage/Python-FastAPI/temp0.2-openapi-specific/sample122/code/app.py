import os
import sqlite3
import logging
from typing import Optional, Dict, Any

from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException, Depends, Header, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field, constr, ValidationError
from passlib.context import CryptContext
import jwt
import uvicorn
import secrets as py_secrets

# -----------------------------------------------------------------------------
# Configuration and Security Setup
# -----------------------------------------------------------------------------

APP_NAME = "Secret Storage"
APP_DESC = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

# Application secret for JWT signing
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate a strong ephemeral secret if not provided.
    # In production, APP_SECRET must be set via environment variables.
    APP_SECRET = py_secrets.token_urlsafe(64)

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour

# Password hashing context (PBKDF2-SHA256)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# SQLite file
DB_PATH = "db.sqlite3"

# Logger
logger = logging.getLogger(APP_NAME)
logging.basicConfig(level=logging.INFO)


# -----------------------------------------------------------------------------
# Database Utilities
# -----------------------------------------------------------------------------

def init_db() -> None:
    """
    Initialize database and create required tables with secure constraints.
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
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
                CREATE TABLE IF NOT EXISTS secrets (
                    user_id INTEGER PRIMARY KEY,
                    secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            """)
            conn.commit()
    except Exception as e:
        logger.exception("Failed to initialize database: %s", e)
        raise


def get_db_connection() -> sqlite3.Connection:
    """
    Creates a new database connection. Connection is per-request and must be closed.
    """
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
    except Exception as e:
        logger.exception("Failed to enable foreign keys: %s", e)
        conn.close()
        raise
    return conn


# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    username: constr(strip_whitespace=True, min_length=3, max_length=50, pattern=r'^[A-Za-z0-9_.-]+$')
    password: constr(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=1, max_length=128)


class SetSecretRequest(BaseModel):
    username: constr(strip_whitespace=True, min_length=3, max_length=50, pattern=r'^[A-Za-z0-9_.-]+$')
    secret: constr(min_length=1, max_length=10000)


# -----------------------------------------------------------------------------
# Utility Functions (Security, JWT)
# -----------------------------------------------------------------------------

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token with claims in `data`.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    token = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decode and validate JWT access token.
    """
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")


def unauthorized_response(message: str = "Invalid authentication token") -> JSONResponse:
    """
    Return a standardized 401 response with `WWW-Authenticate: Bearer`.
    """
    return JSONResponse(status_code=401, content={"message": message}, headers={"WWW-Authenticate": "Bearer"})


# -----------------------------------------------------------------------------
# FastAPI App
# -----------------------------------------------------------------------------

app = FastAPI(title=APP_NAME, description=APP_DESC, version=APP_VERSION)

# CORS - can be restricted in production as needed.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup() -> None:
    try:
        init_db()
        logger.info("Database initialized and application started.")
    except Exception as e:
        logger.exception("Startup error: %s", e)
        # Let the application continue; errors will be surfaced via endpoints.


# -----------------------------------------------------------------------------
# Authentication Dependency
# -----------------------------------------------------------------------------

def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """
    Extract and validate the JWT from Authorization header and load user info from DB.
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authentication scheme")

    token = parts[1]
    payload = decode_access_token(token)

    # Validate presence of required claims
    if "sub" not in payload or "email" not in payload or "username" not in payload:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    user_id = payload["sub"]
    username = payload["username"]
    email = payload["email"]

    # Ensure user exists and matches claims
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, email, username FROM users WHERE id = ?;", (user_id,))
        user_row = cur.fetchone()
        if not user_row:
            raise HTTPException(status_code=401, detail="Invalid authentication token")

        if user_row["email"] != email or user_row["username"] != username:
            raise HTTPException(status_code=401, detail="Invalid authentication token")

        return {"id": user_row["id"], "email": user_row["email"], "username": user_row["username"]}
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------

@app.post(
    "/register",
    tags=["Authentication"],
    summary="User registration",
    description="Register a new user with email, username and password.",
)
def register(req: RegisterRequest):
    """
    Register a new user. Enforces unique email and username, and secure password hashing.
    """
    email_norm = req.email.lower().strip()
    username_norm = req.username.strip()

    conn = get_db_connection()
    try:
        cur = conn.cursor()

        # Check for existing email/username
        cur.execute("SELECT 1 FROM users WHERE email = ?;", (email_norm,))
        if cur.fetchone():
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        cur.execute("SELECT 1 FROM users WHERE username = ?;", (username_norm,))
        if cur.fetchone():
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        password_hash = pwd_context.hash(req.password)

        created_at = datetime.now(timezone.utc).isoformat()
        cur.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (email_norm, username_norm, password_hash, created_at),
        )
        conn.commit()
        return {"message": "Registration successful"}
    except sqlite3.Error as e:
        logger.exception("Database error during registration: %s", e)
        # Avoid leaking internal error details
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    except Exception as e:
        logger.exception("Unexpected error during registration: %s", e)
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    finally:
        conn.close()


@app.post(
    "/login",
    tags=["Authentication"],
    summary="User login",
    description="Authenticate a user with email and password.",
)
def login(req: LoginRequest):
    """
    Login endpoint: verifies credentials and returns JWT access token on success.
    """
    email_norm = req.email.lower().strip()

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?;", (email_norm,))
        user_row = cur.fetchone()
        if not user_row:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

        if not pwd_context.verify(req.password, user_row["password_hash"]):
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

        # Create JWT
        token_payload = {
            "sub": user_row["id"],
            "email": user_row["email"],
            "username": user_row["username"],
            "jti": py_secrets.token_urlsafe(16),
        }
        token = create_access_token(token_payload, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

        return {"token": token, "message": "Login successful"}
    except Exception as e:
        logger.exception("Unexpected error during login: %s", e)
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
    finally:
        conn.close()


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(req: SetSecretRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Set or update the user's secret. Requires Bearer token and username must match token.
    """
    # Authorization check: username in request must match the user in token (CWE-863 mitigation)
    if req.username != current_user["username"]:
        return unauthorized_response("Invalid authentication token")

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        updated_at = datetime.now(timezone.utc).isoformat()

        # Upsert secret: allow only one secret per user (simplifies the schema)
        cur.execute("SELECT 1 FROM secrets WHERE user_id = ?;", (current_user["id"],))
        exists = cur.fetchone() is not None

        if exists:
            cur.execute(
                "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?;",
                (req.secret, updated_at, current_user["id"]),
            )
        else:
            cur.execute(
                "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?);",
                (current_user["id"], req.secret, updated_at),
            )
        conn.commit()
        return {"message": "Secret has been set successfully"}
    except sqlite3.Error as e:
        logger.exception("Database error during set_secret: %s", e)
        # Conceal internal details
        return JSONResponse(status_code=500, content={"message": "An internal error occurred"})
    except Exception as e:
        logger.exception("Unexpected error during set_secret: %s", e)
        return JSONResponse(status_code=500, content={"message": "An internal error occurred"})
    finally:
        conn.close()


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(username: str = Query(..., min_length=3, max_length=50), current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Retrieve the user's secret. Requires Bearer token and username must match token.
    """
    if username.strip() != current_user["username"]:
        return unauthorized_response("Invalid authentication token")

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT secret FROM secrets WHERE user_id = ?;", (current_user["id"],))
        row = cur.fetchone()
        secret_value = row["secret"] if row and "secret" in row.keys() else ""
        return {"secret": secret_value}
    except sqlite3.Error as e:
        logger.exception("Database error during get_secret: %s", e)
        return JSONResponse(status_code=500, content={"message": "An internal error occurred"})
    except Exception as e:
        logger.exception("Unexpected error during get_secret: %s", e)
        return JSONResponse(status_code=500, content={"message": "An internal error occurred"})
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# Custom Exception Handlers
# -----------------------------------------------------------------------------

@app.exception_handler(HTTPException)
def http_exception_handler(request, exc: HTTPException):
    """
    Ensure consistent error response format with 'message' key.
    """
    status_code = exc.status_code
    detail = exc.detail if isinstance(exc.detail, str) else "An error occurred"
    # Map to schema expectations:
    if status_code == 401:
        return unauthorized_response(detail if detail else "Invalid authentication token")
    elif status_code == 400:
        return JSONResponse(status_code=400, content={"message": detail})
    else:
        return JSONResponse(status_code=status_code, content={"message": detail})


@app.exception_handler(ValidationError)
def validation_exception_handler(request, exc: ValidationError):
    """
    Handle request validation errors gracefully (CWE-703).
    """
    return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})


@app.exception_handler(Exception)
def general_exception_handler(request, exc: Exception):
    """
    Generic exception handler to avoid leaking sensitive information (CWE-703).
    """
    logger.exception("Unhandled exception: %s", exc)
    return JSONResponse(status_code=500, content={"message": "An internal error occurred"})


# -----------------------------------------------------------------------------
# Run Server
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)