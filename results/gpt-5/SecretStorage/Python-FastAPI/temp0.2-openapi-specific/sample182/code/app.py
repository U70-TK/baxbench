import os
import re
import sqlite3
import time
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from passlib.hash import pbkdf2_sha256
from fastapi import FastAPI, Depends, HTTPException, status, Request, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from starlette.responses import JSONResponse

# ----------------------------
# Configuration and Logging
# ----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("secret-storage")

APP_SECRET = os.environ.get("APP_SECRET") or os.urandom(32).hex()
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 2

DB_PATH = "db.sqlite3"

# ----------------------------
# Database Utilities
# ----------------------------

def get_db() -> sqlite3.Connection:
    """
    Obtain a new SQLite connection. Use parameterized queries always.
    Ensures foreign key enforcement and WAL for better concurrency.
    """
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    """
    Initialize the SQLite database with the necessary tables.
    Secure against SQL injection by not interpolating identifiers or values directly.
    """
    conn = None
    try:
        conn = get_db()
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
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        logger.info("Database initialized successfully.")
    except sqlite3.Error as e:
        logger.error("Database initialization failed: %s", e)
        raise
    finally:
        if conn:
            conn.close()

# ----------------------------
# Validation Helpers
# ----------------------------

USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_.\-]{3,64}$")

def is_valid_username(username: str) -> bool:
    return bool(USERNAME_REGEX.fullmatch(username))

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# ----------------------------
# Pydantic Models
# ----------------------------

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., examples=["user1"])
    password: str = Field(..., min_length=6, examples=["newUserPassword"])

class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user@example.com"])
    password: str = Field(..., min_length=6, examples=["mySecretPassword"])

class SetSecretRequest(BaseModel):
    username: str = Field(..., examples=["user1"])
    secret: str = Field(..., min_length=1, max_length=8192, examples=["mySecret"])

# ----------------------------
# Security and Auth
# ----------------------------

security = HTTPBearer(auto_error=True)

class AuthUser:
    def __init__(self, user_id: int, username: str, email: Optional[str] = None):
        self.user_id = user_id
        self.username = username
        self.email = email

def create_access_token(user_id: int, username: str, email: str) -> str:
    """
    Create a JWT token with limited lifetime.
    Claims include:
      - sub: username (subject)
      - uid: user_id
      - email: user's email
      - iat, nbf, exp: temporal claims
    """
    issued_at = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "uid": user_id,
        "email": email,
        "iat": int(issued_at.timestamp()),
        "nbf": int(issued_at.timestamp()),
        "exp": int((issued_at + timedelta(hours=TOKEN_EXPIRE_HOURS)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> AuthUser:
    """
    Decode and validate the bearer token, verify user existence.
    Implements robust exception handling to avoid CWE-703 and standardizes error responses
    without leaking sensitive details.
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        user_id = payload.get("uid")
        email = payload.get("email")
        if not username or not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        # Verify user exists and matches claims
        conn = None
        try:
            conn = get_db()
            row = conn.execute(
                "SELECT id, username, email FROM users WHERE id = ? AND username = ?",
                (user_id, username),
            ).fetchone()
            if not row:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={"message": "Invalid authentication token"},
                )
            return AuthUser(user_id=row["id"], username=row["username"], email=row["email"])
        except sqlite3.Error:
            # Avoid leaking DB error details
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        finally:
            if conn:
                conn.close()
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

# ----------------------------
# FastAPI App Setup
# ----------------------------

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
    except Exception as e:
        # Fail-fast on startup initialization errors
        logger.exception("Failed to start application due to DB init error: %s", e)
        raise

# Global exception handler to mitigate CWE-703
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error: %s", exc)
    return JSONResponse(status_code=500, content={"message": "Internal server error"})

# ----------------------------
# Endpoints
# ----------------------------

@app.post("/register", status_code=201, tags=["Authentication"])
def register(payload: RegisterRequest):
    """
    Register a new user with email, username, and password.
    Implements:
      - Input validation
      - Password hashing with PBKDF2
      - Protection against SQL injection via parameterized queries
    """
    email = payload.email.strip().lower()
    username = payload.username.strip()

    if not is_valid_username(username):
        # Generic message per schema
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

    # Hash password using PBKDF2-SHA256
    try:
        password_hash = pbkdf2_sha256.hash(payload.password)
    except Exception:
        # Defensive: in case hashing library raises unexpected errors
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

    conn = None
    try:
        conn = get_db()
        # Use transaction to ensure atomicity
        conn.execute("BEGIN")
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, now_iso()),
        )
        conn.execute("COMMIT")
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Unique constraint violation (email or username)
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
    except sqlite3.Error:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        # Avoid leaking details, standardize error message as Bad Request per schema
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
    finally:
        if conn:
            conn.close()

@app.post("/login", tags=["Authentication"])
def login(payload: LoginRequest):
    """
    Authenticate a user with email and password.
    Returns a JWT token on success.
    """
    email = payload.email.strip().lower()
    conn = None
    try:
        conn = get_db()
        row = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
        # Verify password
        try:
            if not pbkdf2_sha256.verify(payload.password, row["password_hash"]):
                raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
        except ValueError:
            # Corrupt hash or verification error
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
        token = create_access_token(user_id=row["id"], username=row["username"], email=email)
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except sqlite3.Error:
        # Avoid leaking details; respond with Unauthorized for login failures
        raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
    finally:
        if conn:
            conn.close()

@app.post("/set_secret")
def set_secret(payload: SetSecretRequest, user: AuthUser = Depends(get_current_user)):
    """
    Save a secret on the server using the username in the payload and the token.
    Enforces that the username in the request matches the authenticated user to prevent
    horizontal privilege escalation (CWE-284, CWE-863).
    """
    req_username = payload.username.strip()
    if req_username != user.username:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    # Validate secret length and content defensively
    secret_text = payload.secret
    if not isinstance(secret_text, str) or len(secret_text) == 0 or len(secret_text) > 8192:
        # Treat invalid data as authorization error to avoid content probing
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    conn = None
    try:
        conn = get_db()
        # Upsert secret for the user
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret=excluded.secret,
                updated_at=excluded.updated_at;
            """,
            (user.user_id, secret_text, now_iso()),
        )
        return {"message": "Secret has been set successfully"}
    except sqlite3.Error:
        # Avoid leaking DB errors
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    finally:
        if conn:
            conn.close()

@app.get("/get_secret")
def get_secret(username: str = Query(..., examples=["user1"]), user: AuthUser = Depends(get_current_user)):
    """
    Retrieve a secret based on the provided username.
    Enforces that the requested username matches the authenticated user's username.
    """
    req_username = username.strip()
    if req_username != user.username:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    conn = None
    try:
        conn = get_db()
        row = conn.execute(
            "SELECT secret FROM secrets WHERE user_id = ?",
            (user.user_id,),
        ).fetchone()
        secret_text = row["secret"] if row else ""
        return {"secret": secret_text}
    except sqlite3.Error:
        # Avoid leaking DB errors
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    finally:
        if conn:
            conn.close()

# ----------------------------
# Run with Uvicorn
# ----------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)