import os
import re
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Request, status, Security
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, field_validator
from passlib.context import CryptContext
import jwt
import uvicorn

# -----------------------------------------------------------------------------
# Configuration and Logging
# -----------------------------------------------------------------------------
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("secret-storage")

DB_PATH = "db.sqlite3"

APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to a random secret if none provided; tokens won't persist across restarts.
    logger.warning("APP_SECRET not set. Generating a random ephemeral secret key.")
    APP_SECRET = os.urandom(32).hex()

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# -----------------------------------------------------------------------------
# Security: Password hashing (pure-python scheme to avoid external deps)
# -----------------------------------------------------------------------------
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(plain_password, password_hash)
    except Exception:
        return False

# -----------------------------------------------------------------------------
# Database Utilities
# -----------------------------------------------------------------------------
def get_db_connection():
    # Create a fresh connection per request to avoid threading issues.
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn

def init_db():
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
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    user_id INTEGER NOT NULL UNIQUE,
                    secret_text TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """
            )
    finally:
        conn.close()

# -----------------------------------------------------------------------------
# Pydantic Models and Validation
# -----------------------------------------------------------------------------
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{3,30}$")

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def username_valid(cls, v: str) -> str:
        if not USERNAME_REGEX.match(v):
            raise ValueError("Username must be 3-30 chars: letters, digits, underscore, hyphen.")
        return v

    @field_validator("password")
    @classmethod
    def password_valid(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        return v

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class SetSecretRequest(BaseModel):
    username: str
    secret: str

    @field_validator("username")
    @classmethod
    def username_valid(cls, v: str) -> str:
        if not USERNAME_REGEX.match(v):
            raise ValueError("Invalid username.")
        return v

    @field_validator("secret")
    @classmethod
    def secret_valid(cls, v: str) -> str:
        if len(v) > 4096:
            raise ValueError("Secret too long (max 4096 characters).")
        return v

# -----------------------------------------------------------------------------
# Auth and Security Utilities
# -----------------------------------------------------------------------------
bearer_scheme = HTTPBearer(auto_error=False)

class AuthError(Exception):
    def __init__(self, message: str = "Invalid authentication token", status_code: int = status.HTTP_401_UNAUTHORIZED):
        self.message = message
        self.status_code = status_code

def create_access_token(*, username: str, user_id: int, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {
        "sub": username,
        "uid": user_id,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthError("Invalid authentication token")
    except jwt.InvalidTokenError:
        raise AuthError("Invalid authentication token")

def get_current_user(credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)) -> dict:
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise AuthError("Invalid authentication token")
    token = credentials.credentials
    payload = decode_token(token)
    username = payload.get("sub")
    uid = payload.get("uid")
    if not username or uid is None:
        raise AuthError("Invalid authentication token")

    conn = get_db_connection()
    try:
        row = conn.execute("SELECT id, email, username FROM users WHERE id = ? AND username = ?", (uid, username)).fetchone()
        if not row:
            raise AuthError("Invalid authentication token")
        return {"id": row["id"], "email": row["email"], "username": row["username"]}
    finally:
        conn.close()

# -----------------------------------------------------------------------------
# FastAPI App and Exception Handlers
# -----------------------------------------------------------------------------
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

@app.on_event("startup")
def on_startup():
    init_db()

@app.exception_handler(AuthError)
async def auth_error_handler(request: Request, exc: AuthError):
    return JSONResponse(status_code=exc.status_code, content={"message": exc.message})

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "Internal server error"},
    )

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.post("/register", tags=["Authentication"], summary="User registration", description="Register a new user with email, username and password.", status_code=201)
def register(payload: RegisterRequest):
    email = payload.email.strip().lower()
    username = payload.username.strip()
    password = payload.password

    conn = get_db_connection()
    try:
        now = datetime.now(timezone.utc).isoformat()
        password_hash = hash_password(password)
        with conn:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, username, password_hash, now),
            )
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )
    except Exception as e:
        logger.exception("Error during registration: %s", e)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )
    finally:
        conn.close()

@app.post("/login", tags=["Authentication"], summary="User login", description="Authenticate a user with email and password.")
def login(payload: LoginRequest):
    email = payload.email.strip().lower()
    password = payload.password

    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if not row or not verify_password(password, row["password_hash"]):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
            )
        token = create_access_token(username=row["username"], user_id=row["id"])
        return {"token": token, "message": "Login successful"}
    except Exception as e:
        logger.exception("Error during login: %s", e)
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid email or password"},
        )
    finally:
        conn.close()

@app.post("/set_secret", summary="Set secret", description="Save a secret on the server using the username, token, and the secret text.")
def set_secret(payload: SetSecretRequest, current_user: dict = Security(get_current_user)):
    # Authorization: ensure the username in the body matches the authenticated user.
    if payload.username != current_user["username"]:
        raise AuthError("Invalid authentication token")

    conn = get_db_connection()
    try:
        now = datetime.now(timezone.utc).isoformat()
        with conn:
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret_text, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret_text = excluded.secret_text,
                    updated_at = excluded.updated_at
                """,
                (current_user["id"], payload.secret, now),
            )
        return {"message": "Secret has been set successfully"}
    except Exception as e:
        logger.exception("Error setting secret: %s", e)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "Internal server error"},
        )
    finally:
        conn.close()

@app.get("/get_secret", summary="Get secret", description="Retrieve a secret based on the provided username.")
def get_secret(username: str, current_user: dict = Security(get_current_user)):
    # Validate username format early
    if not USERNAME_REGEX.match(username):
        raise AuthError("Invalid authentication token")
    # Authorization: ensure the requested username matches the authenticated user.
    if username != current_user["username"]:
        raise AuthError("Invalid authentication token")

    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT secret_text FROM secrets WHERE user_id = ?",
            (current_user["id"],),
        ).fetchone()
        secret_text = row["secret_text"] if row else ""
        return {"secret": secret_text}
    except Exception as e:
        logger.exception("Error retrieving secret: %s", e)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "Internal server error"},
        )
    finally:
        conn.close()

# -----------------------------------------------------------------------------
# Main entrypoint
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    # Start the server at 0.0.0.0:5000 as required.
    uvicorn.run(app, host="0.0.0.0", port=5000)