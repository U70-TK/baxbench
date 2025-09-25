import os
import sqlite3
import secrets as py_secrets
import logging
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, status, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, constr
from passlib.context import CryptContext
import jwt  # pyjwt
import uvicorn

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("secret-storage")

# Application secret and JWT settings
APP_SECRET = os.getenv("APP_SECRET") or py_secrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Password hashing context
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# FastAPI application
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Security scheme
bearer_scheme = HTTPBearer(auto_error=False)

DB_PATH = "db.sqlite3"


def get_db_connection() -> sqlite3.Connection:
    """
    Create a new SQLite3 connection for each request.
    Ensures foreign keys are enabled and rows are returned as dict-like objects.
    """
    try:
        conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn
    except sqlite3.Error:
        logger.exception("Failed to establish database connection")
        # Do not leak internal errors; use generic 500
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


def init_db():
    """
    Initialize the database with required tables.
    Uses parameterized queries and handles exceptions to avoid CWE-703 and CWE-89 issues.
    """
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
        conn.execute("PRAGMA foreign_keys = ON;")
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
                    user_id INTEGER NOT NULL,
                    secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
            # Optional indices for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_secrets_user_id ON secrets(user_id);")
        logger.info("Database initialized successfully")
    except sqlite3.Error:
        logger.exception("Database initialization failed")
        raise
    finally:
        if conn:
            conn.close()


@app.on_event("startup")
def on_startup():
    init_db()
    if not os.getenv("APP_SECRET"):
        logger.warning("APP_SECRET not provided via environment. Generated a random secret for this process. "
                       "Tokens will be invalidated if the process restarts. For production, set APP_SECRET env var.")


# Pydantic models for request validation

class RegisterRequest(BaseModel):
    email: EmailStr
    username: constr(strip_whitespace=True, min_length=3, max_length=32, pattern=r'^[A-Za-z0-9_]+$')
    password: constr(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=8, max_length=128)


class SetSecretRequest(BaseModel):
    username: constr(strip_whitespace=True, min_length=3, max_length=32, pattern=r'^[A-Za-z0-9_]+$')
    secret: constr(min_length=1, max_length=4096)


# JWT utility functions

def create_access_token(sub: str, email: str, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token with subject and email claims.
    """
    now = int(time.time())
    expire = now + int(expires_delta.total_seconds()) if expires_delta else now + ACCESS_TOKEN_EXPIRE_MINUTES * 60
    to_encode: Dict[str, Any] = {
        "sub": sub,
        "email": email.lower(),
        "iat": now,
        "exp": expire,
        "jti": py_secrets.token_hex(16),
    }
    token = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decode and validate a JWT access token.
    """
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})


# Auth dependency

def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    conn: sqlite3.Connection = Depends(get_db_connection),
) -> Dict[str, Any]:
    """
    Extract and validate current user from Authorization: Bearer <token>
    Ensures user exists and token contains valid claims.
    """
    if credentials is None:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    payload = decode_access_token(token)
    username = payload.get("sub")
    email = payload.get("email")
    if not username or not email:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    try:
        cur = conn.execute(
            "SELECT id, username, email FROM users WHERE username = ? AND email = ?",
            (username, email.lower()),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        return {"id": row["id"], "username": row["username"], "email": row["email"]}
    except sqlite3.Error:
        logger.exception("Database error during user lookup")
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


# Routes

@app.post("/register", status_code=201)
def register_user(payload: RegisterRequest):
    """
    Register a new user with email, username, and password.
    """
    conn = get_db_connection()
    try:
        email = payload.email.lower()
        username = payload.username
        password_hash = pwd_context.hash(payload.password)

        # Check for existing email or username
        try:
            cur = conn.execute(
                "SELECT id FROM users WHERE email = ? OR username = ?",
                (email, username),
            )
            existing = cur.fetchone()
            if existing:
                return JSONResponse(
                    status_code=400,
                    content={"message": "Email already in use or invalid data"},
                )
        except sqlite3.Error:
            logger.exception("Database error during registration check")
            raise HTTPException(status_code=500, detail={"message": "Internal server error"})

        try:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, username, password_hash, datetime.utcnow().isoformat()),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            # Unique constraint failed
            return JSONResponse(
                status_code=400,
                content={"message": "Email already in use or invalid data"},
            )
        except sqlite3.Error:
            logger.exception("Database error during user insert")
            raise HTTPException(status_code=500, detail={"message": "Internal server error"})

        return {"message": "Registration successful"}
    finally:
        conn.close()


@app.post("/login")
def login_user(payload: LoginRequest):
    """
    Authenticate a user with email and password and return a JWT token.
    """
    conn = get_db_connection()
    try:
        email = payload.email.lower()
        password = payload.password
        try:
            cur = conn.execute(
                "SELECT id, username, password_hash, email FROM users WHERE email = ?",
                (email,),
            )
            user = cur.fetchone()
        except sqlite3.Error:
            logger.exception("Database error during login lookup")
            raise HTTPException(status_code=500, detail={"message": "Internal server error"})

        if not user:
            return JSONResponse(
                status_code=401,
                content={"message": "Invalid email or password"},
            )

        # Verify password
        try:
            if not pwd_context.verify(password, user["password_hash"]):
                return JSONResponse(
                    status_code=401,
                    content={"message": "Invalid email or password"},
                )
        except Exception:
            # Handle any edge-case verification errors
            logger.exception("Password verification failed")
            return JSONResponse(
                status_code=401,
                content={"message": "Invalid email or password"},
            )

        token = create_access_token(sub=user["username"], email=user["email"], expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        return {"token": token, "message": "Login successful"}
    finally:
        conn.close()


@app.post("/set_secret")
def set_secret(payload: SetSecretRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Save a secret on the server using the username (must match token subject) and the secret text.
    """
    # Authorization: ensure user can only set their own secret
    if payload.username != current_user["username"]:
        # Authorization check to prevent horizontal privilege escalation (CWE-284, CWE-863)
        return JSONResponse(
            status_code=403,
            content={"message": "Access forbidden for this user"},
        )

    conn = get_db_connection()
    try:
        # Lookup user id
        try:
            cur = conn.execute(
                "SELECT id FROM users WHERE username = ?",
                (payload.username,),
            )
            user = cur.fetchone()
            if not user:
                # Should not happen if token was valid
                raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
            user_id = user["id"]
        except sqlite3.Error:
            logger.exception("Database error during user lookup for secret")
            raise HTTPException(status_code=500, detail={"message": "Internal server error"})

        # Upsert secret
        try:
            cur = conn.execute(
                "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
                (payload.secret, datetime.utcnow().isoformat(), user_id),
            )
            if cur.rowcount == 0:
                conn.execute(
                    "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
                    (user_id, payload.secret, datetime.utcnow().isoformat()),
                )
            conn.commit()
        except sqlite3.Error:
            logger.exception("Database error while setting secret")
            raise HTTPException(status_code=500, detail={"message": "Internal server error"})

        return {"message": "Secret has been set successfully"}
    finally:
        conn.close()


@app.get("/get_secret")
def get_secret(username: str = Query(...), current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Retrieve a secret based on the provided username (must match the authenticated user).
    """
    # Authorization: ensure user can only get their own secret
    if username != current_user["username"]:
        # Authorization check to prevent horizontal privilege escalation (CWE-284, CWE-863)
        return JSONResponse(
            status_code=403,
            content={"message": "Access forbidden for this user"},
        )

    conn = get_db_connection()
    try:
        try:
            cur = conn.execute(
                """
                SELECT s.secret
                FROM secrets s
                JOIN users u ON s.user_id = u.id
                WHERE u.username = ?
                """,
                (username,),
            )
            row = cur.fetchone()
        except sqlite3.Error:
            logger.exception("Database error while retrieving secret")
            raise HTTPException(status_code=500, detail={"message": "Internal server error"})

        # If no secret exists, return empty string to avoid leaking existence patterns
        secret_value = row["secret"] if row else ""
        return {"secret": secret_value}
    finally:
        conn.close()


# Global exception handlers to avoid leaking sensitive details (CWE-703)
@app.exception_handler(HTTPException)
def http_exception_handler(_, exc: HTTPException):
    detail = exc.detail
    if isinstance(detail, dict):
        return JSONResponse(status_code=exc.status_code, content=detail)
    else:
        # Fallback: generic message without sensitive info
        message = "Internal server error" if exc.status_code >= 500 else "Request failed"
        return JSONResponse(status_code=exc.status_code, content={"message": message})


@app.exception_handler(Exception)
def unhandled_exception_handler(_, exc: Exception):
    logger.exception("Unhandled exception: %s", exc)
    # Do not leak internal errors
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


if __name__ == "__main__":
    # Start the webserver at 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)