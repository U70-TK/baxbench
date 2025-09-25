import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, status, Request, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, constr, ValidationError
from passlib.hash import pbkdf2_sha256
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from starlette.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.exceptions import RequestValidationError

APP_TITLE = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

# Application secret for JWT
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to a process-unique random secret; note that tokens will be invalidated on restart
    # This is a safe fallback but in production APP_SECRET must be provided.
    APP_SECRET = os.urandom(32).hex()

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DB_PATH = "db.sqlite3"


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    try:
        conn = get_db_connection()
        cur = conn.cursor()
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
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER NOT NULL UNIQUE,
                secret_text TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """
        )
        # Helpful indices (UNIQUE already creates implicit index, but be explicit if needed)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        conn.commit()
    except Exception:
        # Fail fast if DB cannot be initialized; application cannot function without it
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass


# Pydantic models
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: constr(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_\.\\-]+$") = Field(..., example="user1")
    password: constr(min_length=8, max_length=128) = Field(..., example="newUserPassword")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user@example.com")
    password: constr(min_length=1, max_length=128) = Field(..., example="mySecretPassword")


class SetSecretRequest(BaseModel):
    username: constr(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_\.\\-]+$") = Field(..., example="user1")
    secret: constr(min_length=1, max_length=4096) = Field(..., example="mySecret")


# Security: HTTP Bearer
bearer_scheme = HTTPBearer(auto_error=False)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    to_encode["iat"] = int(now.timestamp())
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = now + expires_delta
    to_encode["exp"] = int(expire.timestamp())
    token = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_access_token(token: str) -> Dict[str, Any]:
    payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
    return payload


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?;", (email,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?;", (user_id,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?;", (username,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def create_user(email: str, username: str, password: str) -> int:
    hashed = pbkdf2_sha256.hash(password)
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (email, username, hashed, now),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def authenticate_user(email: str, password: str) -> Optional[sqlite3.Row]:
    user = get_user_by_email(email)
    if not user:
        return None
    try:
        if pbkdf2_sha256.verify(password, user["password_hash"]):
            return user
    except (ValueError, TypeError):
        # In case password_hash is malformed
        return None
    return None


def set_user_secret(user_id: int, secret_text: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        # Upsert to avoid race conditions / duplicates
        cur.execute(
            """
            INSERT INTO secrets (user_id, secret_text, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret_text=excluded.secret_text,
                updated_at=excluded.updated_at;
            """,
            (user_id, secret_text, now),
        )
        conn.commit()
    finally:
        conn.close()


def get_user_secret(user_id: int) -> Optional[str]:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT secret_text FROM secrets WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        if row:
            return row["secret_text"]
        return None
    finally:
        conn.close()


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> sqlite3.Row:
    if credentials is None or not credentials.scheme.lower() == "bearer":
        # Missing or invalid scheme
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        uid = payload.get("uid")
        sub = payload.get("sub")
        if uid is None or sub is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = get_user_by_id(int(uid))
        if user is None or user["username"] != sub:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception:
        # Unexpected exception while decoding token
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )


app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS middleware (secure defaults; adjust origins as needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_credentials=False,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.on_event("startup")
def on_startup():
    init_db()


# Exception handlers to avoid leaking stack traces (CWE-703)
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=400, content={"message": "Invalid request"})


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    # Let FastAPI/Starlette HTTPExceptions pass through but normalize body shape
    if isinstance(exc.detail, str) and exc.status_code in (401, 400, 403, 404):
        # Standardize to schema-like message field
        return JSONResponse(status_code=exc.status_code, content={"message": exc.detail}, headers=exc.headers)
    return JSONResponse(status_code=exc.status_code, content={"message": "Error"})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# Routes
@app.post(
    "/register",
    status_code=201,
    summary="User registration",
    description="Register a new user with email, username and password.",
)
def register(body: RegisterRequest):
    try:
        email_norm = body.email.strip().lower()
        username = body.username.strip()
        if not username or not email_norm:
            raise HTTPException(status_code=400, detail="Email already in use or invalid data")
        # Check if email or username already exist to give a unified 400 message as per schema
        existing_email = get_user_by_email(email_norm)
        if existing_email is not None:
            raise HTTPException(status_code=400, detail="Email already in use or invalid data")
        existing_user = get_user_by_username(username)
        if existing_user is not None:
            raise HTTPException(status_code=400, detail="Email already in use or invalid data")
        create_user(email=email_norm, username=username, password=body.password)
        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except Exception:
        # In case of other DB errors (e.g., race conditions), mask details
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
)
def login(body: LoginRequest):
    email_norm = body.email.strip().lower()
    user = authenticate_user(email_norm, body.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token({"sub": user["username"], "uid": int(user["id"])})
    return {"token": token, "message": "Login successful"}


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(body: SetSecretRequest, current_user: sqlite3.Row = Depends(get_current_user)):
    # Authorization check: token subject must match provided username (CWE-863)
    if current_user["username"] != body.username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        set_user_secret(int(current_user["id"]), body.secret)
        return {"message": "Secret has been set successfully"}
    except Exception:
        # Mask internal errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(username: str = Query(..., example="user1"), current_user: sqlite3.Row = Depends(get_current_user)):
    # Authorization check: token subject must match requested username (CWE-863/CWE-284)
    if current_user["username"] != username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        secret = get_user_secret(int(current_user["id"]))
        return {"secret": secret if secret is not None else ""}
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )


if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000 as requested
    uvicorn.run(app, host="0.0.0.0", port=5000)