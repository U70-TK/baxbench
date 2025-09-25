import os
import sqlite3
import secrets as pysecrets
from datetime import datetime, timedelta
from typing import Optional, Tuple

import jwt
from fastapi import FastAPI, Depends, HTTPException, status, Request, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import uvicorn

# Application initialization
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Security headers middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            response = await call_next(request)
        except Exception:
            # General fallback to avoid leaking internal errors (CWE-703)
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"message": "Internal server error"},
            )
        # Add strict security headers to reduce common browser-based risks
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# Configuration
DB_NAME = "db.sqlite3"
APP_SECRET = os.getenv("APP_SECRET") or pysecrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = 60

# Password hashing context: use PBKDF2-SHA256 (pure-python, strong KDF)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# Auth bearer dependency
bearer_scheme = HTTPBearer(auto_error=False)

# Database utilities
def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_NAME, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Defensive pragmas for reliability
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn

def init_db():
    conn = get_connection()
    try:
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
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
    finally:
        conn.close()

init_db()

# Models
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., min_length=3, max_length=30, pattern=r"^[A-Za-z0-9_]+$", example="user1")
    password: str = Field(..., min_length=8, max_length=128, example="newUserPassword")

class RegisterResponse(BaseModel):
    message: str = "Registration successful"

class ErrorMessage(BaseModel):
    message: str

class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: str = Field(..., min_length=1, max_length=128, example="pass1")

class LoginResponse(BaseModel):
    token: str
    message: str = "Login successful"

class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=30, pattern=r"^[A-Za-z0-9_]+$", example="user1")
    secret: str = Field(..., min_length=1, max_length=8192, example="mySecret")

class SetSecretResponse(BaseModel):
    message: str = "Secret has been set successfully"

class GetSecretResponse(BaseModel):
    secret: str

# Helper functions
def create_user(email: str, username: str, password_hash: str) -> bool:
    conn = get_connection()
    try:
        now = datetime.utcnow().isoformat()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, now),
        )
        return True
    except sqlite3.IntegrityError:
        # Uniqueness violation
        return False
    except Exception:
        # Defensive handling (CWE-703)
        return False
    finally:
        conn.close()

def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    conn = get_connection()
    try:
        cur = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()

def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_connection()
    try:
        cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()

def upsert_secret(user_id: int, secret: str) -> bool:
    conn = get_connection()
    try:
        now = datetime.utcnow().isoformat()
        # Use INSERT OR REPLACE for idempotent single secret per user
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET secret = excluded.secret, updated_at = excluded.updated_at;
            """,
            (user_id, secret, now),
        )
        return True
    except Exception:
        return False
    finally:
        conn.close()

def read_secret(user_id: int) -> Optional[str]:
    conn = get_connection()
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        if row:
            return row["secret"]
        return None
    finally:
        conn.close()

def create_access_token(user_id: int, username: str) -> str:
    now = datetime.utcnow()
    payload = {
        "sub": username,  # subject is the username
        "uid": user_id,   # explicit user id claim
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXP_MINUTES)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_token(token: str) -> Tuple[int, str]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        uid = payload.get("uid")
        sub = payload.get("sub")
        if not isinstance(uid, int) or not isinstance(sub, str):
            raise jwt.InvalidTokenError("Invalid token payload")
        return uid, sub
    except jwt.ExpiredSignatureError:
        # Token expired
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=None,
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        # Bad token
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=None,
            headers={"WWW-Authenticate": "Bearer"},
        )

# Dependencies
def get_auth_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> Tuple[int, str]:
    if credentials is None or not credentials.credentials:
        # Unauthorized - missing token (CWE-284)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=None,
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    uid, sub = decode_token(token)
    # Ensure user still exists
    user = get_user_by_username(sub)
    if not user or user["id"] != uid:
        # Prevent stale/inconsistent tokens (CWE-863)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=None,
            headers={"WWW-Authenticate": "Bearer"},
        )
    return uid, sub

# Routes
@app.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"model": ErrorMessage, "description": "Bad Request"},
    },
)
def register(req: RegisterRequest):
    # Hash password securely (CWE-522)
    password_hash = pwd_context.hash(req.password)

    created = create_user(req.email, req.username, password_hash)
    if not created:
        # Avoid information leakage: generic error message
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )
    return {"message": "Registration successful"}

@app.post(
    "/login",
    response_model=LoginResponse,
    responses={
        401: {"model": ErrorMessage, "description": "Unauthorized"},
    },
)
def login(req: LoginRequest):
    user = get_user_by_email(req.email)
    if not user:
        # Uniform error to prevent user enumeration (CWE-284/CWE-522)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    # Verify password
    try:
        valid = pwd_context.verify(req.password, user["password_hash"])
    except Exception:
        valid = False
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    token = create_access_token(user["id"], user["username"])
    return {"token": token, "message": "Login successful"}

@app.post(
    "/set_secret",
    response_model=SetSecretResponse,
    responses={
        401: {"model": ErrorMessage, "description": "Unauthorized"},
    },
)
def set_secret(req: SetSecretRequest, auth: Tuple[int, str] = Depends(get_auth_user)):
    uid, sub = auth
    # Enforce that a user can only set their own secret (CWE-284/CWE-863)
    if req.username != sub:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    # Confirm user exists (already ensured in dependency), but re-verify to be robust
    user = get_user_by_username(req.username)
    if not user or user["id"] != uid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    success = upsert_secret(uid, req.secret)
    if not success:
        # Defensive error handling (CWE-703)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )

    return {"message": "Secret has been set successfully"}

@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
    responses={
        401: {"model": ErrorMessage, "description": "Unauthorized"},
    },
)
def get_secret(username: str = Query(..., min_length=3, max_length=30, pattern=r"^[A-Za-z0-9_]+$", example="user1"),
               auth: Tuple[int, str] = Depends(get_auth_user)):
    uid, sub = auth
    # Enforce that a user can only get their own secret (CWE-284/CWE-863)
    if username != sub:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    # Retrieve secret safely (CWE-89 via parameterized query)
    user = get_user_by_username(username)
    if not user or user["id"] != uid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    secret = read_secret(uid)
    # If no secret stored yet, return empty string rather than an error
    return {"secret": secret or ""}

# Override default exception handler to conform to response formats for some errors
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Map detail to payload using "message" key as per schema
    # For 401 and 400 we return {"message": "..."}
    # For 500, we also return {"message": "..."} to avoid leaking internal details.
    message = None
    if exc.detail is None:
        # Provide standard messages where detail is None
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            message = "Invalid authentication token"
        else:
            message = "Internal server error"
    else:
        message = str(exc.detail)

    return JSONResponse(
        status_code=exc.status_code,
        content={"message": message},
        headers=exc.headers,
    )

# Root health endpoint (optional)
@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    # Start the web server on 0.0.0.0:5000 without streaming responses
    uvicorn.run(app, host="0.0.0.0", port=5000)