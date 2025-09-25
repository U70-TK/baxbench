import os
import sqlite3
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from starlette.middleware.base import BaseHTTPMiddleware
import jwt  # pyjwt
from passlib.hash import pbkdf2_sha256

# -----------------------------------------------------------------------------
# Configuration and Security
# -----------------------------------------------------------------------------

APP_NAME = "Secret Storage"
DB_PATH = "db.sqlite3"

# Obtain application secret
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to an ephemeral secret (not suitable for production)
    APP_SECRET = uuid.uuid4().hex + uuid.uuid4().hex

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Pepper for password hashing (derived from APP_SECRET)
PASSWORD_PEPPER = APP_SECRET

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(APP_NAME)

# -----------------------------------------------------------------------------
# Database Utilities
# -----------------------------------------------------------------------------

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db() -> None:
    conn = get_db_connection()
    try:
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
                    user_id INTEGER PRIMARY KEY,
                    secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
    except Exception as e:
        logger.exception("Failed to initialize database: %s", e)
        raise
    finally:
        conn.close()

# -----------------------------------------------------------------------------
# Security Helpers
# -----------------------------------------------------------------------------

def hash_password(password: str) -> str:
    # Use PBKDF2-SHA256 with adequate iterations and pepper
    return pbkdf2_sha256.using(rounds=200_000).hash(password + PASSWORD_PEPPER)

def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password + PASSWORD_PEPPER, password_hash)
    except Exception:
        return False

def create_access_token(*, subject: str, user_id: int, email: str, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode = {
        "sub": subject,
        "uid": user_id,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": uuid.uuid4().hex,
    }
    token = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

# -----------------------------------------------------------------------------
# FastAPI App Setup
# -----------------------------------------------------------------------------

app = FastAPI(
    title=APP_NAME,
    version="1.0.0",
    description="A secure cloud storage app for string secrets.",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # Basic security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        # HSTS is inert over plain HTTP but included as best practice for HTTPS deployments
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# -----------------------------------------------------------------------------
# Pydantic Models
# -----------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_]+$", examples=["user1"])
    password: str = Field(..., min_length=1, examples=["newUserPassword"])

class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr = Field(..., examples=["user@example.com"])
    password: str = Field(..., min_length=1, examples=["mySecretPassword"])

class SetSecretRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_]+$", examples=["user1"])
    secret: str = Field(..., min_length=0, max_length=8192, examples=["mySecret"])

# -----------------------------------------------------------------------------
# Authentication Dependency
# -----------------------------------------------------------------------------

http_bearer = HTTPBearer(auto_error=False)

def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer)) -> dict:
    if credentials is None or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    payload = decode_access_token(token)

    username = payload.get("sub")
    user_id = payload.get("uid")
    email = payload.get("email")
    if not username or not user_id or not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    # Ensure the user still exists
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username FROM users WHERE id = ? AND username = ? AND email = ?", (user_id, username, email))
        row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        return {"id": row["id"], "email": row["email"], "username": row["username"], "token_payload": payload}
    finally:
        conn.close()

# -----------------------------------------------------------------------------
# Exception Handlers
# -----------------------------------------------------------------------------

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error: %s", exc)
    # Do not leak internal details
    return JSONResponse(status_code=500, content={"message": "Internal server error"})

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@app.post("/register", status_code=201, tags=["Authentication"])
def register(payload: RegisterRequest):
    email = payload.email.strip().lower()
    username = payload.username.strip()
    password = payload.password

    password_hash = hash_password(password)
    created_at = datetime.now(timezone.utc).isoformat()

    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, username, password_hash, created_at),
            )
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Unique constraint failed for email or username or invalid data
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
    except Exception:
        # Ensure we return a controlled error
        raise
    finally:
        conn.close()

@app.post("/login", status_code=200, tags=["Authentication"])
def login(payload: LoginRequest):
    email = payload.email.strip().lower()
    password = payload.password

    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
        if not verify_password(password, row["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
        token = create_access_token(subject=row["username"], user_id=row["id"], email=row["email"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        raise
    finally:
        conn.close()

@app.post("/set_secret", status_code=200)
def set_secret(payload: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    # Authorization check: user can only set their own secret
    if payload.username != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        updated_at = datetime.now(timezone.utc).isoformat()
        with conn:
            # Upsert secret for user
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret=excluded.secret,
                    updated_at=excluded.updated_at
                """,
                (current_user["id"], payload.secret, updated_at),
            )
        return {"message": "Secret has been set successfully"}
    except Exception:
        raise
    finally:
        conn.close()

@app.get("/get_secret", status_code=200)
def get_secret(username: str, current_user: dict = Depends(get_current_user)):
    # Authorization check: user can only get their own secret
    if username != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        cur = conn.execute(
            """
            SELECT s.secret
            FROM secrets s
            JOIN users u ON u.id = s.user_id
            WHERE u.username = ?
            """,
            (username,),
        )
        row = cur.fetchone()
        if not row:
            # Secret not set yet; return empty string to avoid user enumeration through messages
            return {"secret": ""}
        return {"secret": row["secret"]}
    except Exception:
        raise
    finally:
        conn.close()

# -----------------------------------------------------------------------------
# Startup
# -----------------------------------------------------------------------------

@app.on_event("startup")
def on_startup():
    init_db()
    logger.info("%s is starting up.", APP_NAME)

# -----------------------------------------------------------------------------
# Entrypoint
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000 as required
    uvicorn.run(app, host="0.0.0.0", port=5000)