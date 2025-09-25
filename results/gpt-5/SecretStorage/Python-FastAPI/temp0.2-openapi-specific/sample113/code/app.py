import os
import sqlite3
import re
import secrets as py_secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
import jwt  # pyjwt
from passlib.context import CryptContext
import uvicorn

# Configuration
DB_PATH = "db.sqlite3"
APP_SECRET = os.getenv("APP_SECRET") or py_secrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 3600  # 1 hour

# Initialize FastAPI app
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Minimal CORS (allow all for demo; adjust as needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, set specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Password hashing context (PBKDF2-SHA256 - no external binary required)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


# Database utilities
def get_db_connection() -> sqlite3.Connection:
    """
    Returns a new SQLite connection with secure defaults and row factory.
    Ensures foreign keys enforcement and WAL journal for basic concurrency.
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
    except sqlite3.Error:
        # Even if pragmas fail, continue with defaults
        pass
    return conn


def init_db():
    conn = get_db_connection()
    try:
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
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_secrets_user_id ON secrets(user_id)")
    except sqlite3.Error as e:
        # If DB init fails, raise to crash early - better than running with broken storage (CWE-703 mitigation)
        raise RuntimeError(f"Database initialization error: {e}")
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# Models
USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")


class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=8, max_length=128)

    def validate_business(self) -> Optional[str]:
        # Explicit username format validation
        if not USERNAME_REGEX.fullmatch(self.username):
            return "Invalid username format"
        # Basic password policy checks
        # At least one letter and one number (optional but recommended)
        if not re.search(r"[A-Za-z]", self.password) or not re.search(r"\d", self.password):
            return "Password must contain at least one letter and one digit"
        return None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    secret: str = Field(..., min_length=1, max_length=4096)

    def validate_business(self) -> Optional[str]:
        if not USERNAME_REGEX.fullmatch(self.username):
            return "Invalid username format"
        return None


# Security utilities
def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    to_encode["iat"] = int(now.timestamp())
    expire = now + (expires_delta if expires_delta else timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS))
    to_encode["exp"] = int(expire.timestamp())
    token = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})


def bearer_auth_dependency(request: Request) -> Dict[str, Any]:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    token = auth_header[7:].strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    claims = decode_token(token)
    return claims


# Helper responses
def json_message(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"message": message})


# Endpoints
@app.post("/register", tags=["Authentication"])
def register(payload: RegisterRequest):
    """
    Register a new user with email, username, and password.
    """
    validation_error = payload.validate_business()
    if validation_error:
        return json_message(status_code=status.HTTP_400_BAD_REQUEST, message="Email already in use or invalid data")

    email_norm = payload.email.lower().strip()
    username_norm = payload.username.strip()

    # Hash the password securely (CWE-522 mitigation)
    try:
        password_hash = pwd_context.hash(payload.password)
    except Exception:
        # If hashing fails, don't proceed
        return json_message(status_code=status.HTTP_400_BAD_REQUEST, message="Email already in use or invalid data")

    conn = get_db_connection()
    try:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email_norm, username_norm, password_hash, now),
        )
        return JSONResponse(status_code=status.HTTP_201_CREATED, content={"message": "Registration successful"})
    except sqlite3.IntegrityError:
        # Unique constraint violation (email or username already used)
        return json_message(status_code=status.HTTP_400_BAD_REQUEST, message="Email already in use or invalid data")
    except sqlite3.Error:
        # Other DB errors (CWE-703 mitigation)
        return json_message(status_code=status.HTTP_400_BAD_REQUEST, message="Email already in use or invalid data")
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.post("/login", tags=["Authentication"])
def login(payload: LoginRequest):
    """
    Authenticate a user with email and password.
    """
    email_norm = payload.email.lower().strip()
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, username, password_hash FROM users WHERE email = ?", (email_norm,))
        row = cur.fetchone()
        if not row:
            # Avoid user enumeration (CWE-522 and general best practice)
            return json_message(status_code=status.HTTP_401_UNAUTHORIZED, message="Invalid email or password")
        stored_hash = row["password_hash"]
        try:
            valid = pwd_context.verify(payload.password, stored_hash)
        except Exception:
            valid = False
        if not valid:
            return json_message(status_code=status.HTTP_401_UNAUTHORIZED, message="Invalid email or password")
        # Create JWT with limited lifetime
        token = create_access_token({"sub": row["username"], "uid": row["id"], "email": email_norm})
        return JSONResponse(status_code=status.HTTP_200_OK, content={"token": token, "message": "Login successful"})
    except sqlite3.Error:
        return json_message(status_code=status.HTTP_401_UNAUTHORIZED, message="Invalid email or password")
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.post("/set_secret")
def set_secret(payload: SetSecretRequest, claims: Dict[str, Any] = Depends(bearer_auth_dependency)):
    """
    Save a secret on the server using the username from the payload and the Bearer token.
    Authorization: Bearer <token>, subject must match the provided username (CWE-863/CWE-284 mitigation).
    """
    validation_error = payload.validate_business()
    if validation_error:
        # Do not leak validation details in auth-protected operations
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    if claims.get("sub") != payload.username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    username_norm = payload.username.strip()
    secret_text = payload.secret

    conn = get_db_connection()
    try:
        cur_user = conn.execute("SELECT id FROM users WHERE username = ?", (username_norm,))
        user_row = cur_user.fetchone()
        if not user_row:
            # If the token sub doesn't correspond to an existing user, treat as invalid token
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        user_id = user_row["id"]
        now = datetime.now(timezone.utc).isoformat()

        # Try update first
        cur_update = conn.execute(
            "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
            (secret_text, now, user_id),
        )
        if cur_update.rowcount == 0:
            # Insert if no existing secret
            conn.execute(
                "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
                (user_id, secret_text, now),
            )
        return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Secret has been set successfully"})
    except HTTPException:
        raise
    except sqlite3.Error:
        # Treat database errors as auth failure to avoid leaking storage status
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.get("/get_secret")
def get_secret(username: str, claims: Dict[str, Any] = Depends(bearer_auth_dependency)):
    """
    Retrieve a secret based on the provided username.
    Authorization: Bearer <token>, subject must match the requested username (CWE-863/CWE-284 mitigation).
    """
    if not username or not USERNAME_REGEX.fullmatch(username):
        # Do not expose validation specifics; treat as invalid token per spec's 401 response
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    if claims.get("sub") != username:
        # User cannot access others' secrets
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        cur_user = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
        user_row = cur_user.fetchone()
        if not user_row:
            # Do not reveal existence of user; return empty secret to conform with 200 contract
            return JSONResponse(status_code=status.HTTP_200_OK, content={"secret": ""})
        user_id = user_row["id"]
        cur_secret = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        secret_row = cur_secret.fetchone()
        secret_value = secret_row["secret"] if secret_row else ""
        return JSONResponse(status_code=status.HTTP_200_OK, content={"secret": secret_value})
    except sqlite3.Error:
        # Treat errors as invalid auth to avoid information leakage
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    finally:
        try:
            conn.close()
        except Exception:
            pass


# Error handlers (CWE-703 mitigation - graceful failure)
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Avoid leaking internals; return sanitized message
    return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"message": "Internal Server Error"})


if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)