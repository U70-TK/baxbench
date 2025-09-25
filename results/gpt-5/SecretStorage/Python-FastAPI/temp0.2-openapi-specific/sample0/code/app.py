import os
import sqlite3
import secrets
import sys
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Request, Body, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
import jwt  # PyJWT

# =========================
# Configuration and Security
# =========================

APP_TITLE = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"
DB_PATH = "db.sqlite3"
JWT_ALGORITHM = "HS256"

# Load secret from environment; generate strong ephemeral secret if not provided.
APP_SECRET: str = os.getenv("APP_SECRET") or secrets.token_urlsafe(64)

# Password hashing context; pbkdf2_sha256 does not require external native modules.
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# =========================
# FastAPI App Initialization
# =========================

app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    contact=None,
    license_info=None,
)

# CORS - keep restrictive by default; adjust as needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=[],  # update as needed
    allow_credentials=True,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# ===================================
# Database helpers and initialization
# ===================================

def dict_from_row(row: sqlite3.Row) -> Dict[str, Any]:
    return {k: row[k] for k in row.keys()}

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass

def init_db():
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        # Safer SQLite settings
        cur.execute("PRAGMA foreign_keys = ON;")
        try:
            cur.execute("PRAGMA journal_mode = WAL;")
        except sqlite3.DatabaseError:
            # Some environments may not allow changing journal mode; ignore.
            pass
        try:
            cur.execute("PRAGMA synchronous = NORMAL;")
        except sqlite3.DatabaseError:
            pass

        # Users table
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
        # Secrets table - one secret per user
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER PRIMARY KEY,
                secret_text TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    except Exception as e:
        print(f"Database initialization failed: {e}", file=sys.stderr, flush=True)
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass

@app.on_event("startup")
def on_startup():
    init_db()

# ===============
# Data Models
# ===============

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., example="user1")
    password: str = Field(..., example="newUserPassword")

class RegisterResponse(BaseModel):
    message: str = Field(..., example="Registration successful")

class ErrorResponse(BaseModel):
    message: str

class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: str = Field(..., example="pass1")

class LoginResponse(BaseModel):
    token: str = Field(..., example="jwt-token-abc123")
    message: str = Field(..., example="Login successful")

class SetSecretRequest(BaseModel):
    username: str = Field(..., example="user1")
    secret: str = Field(..., example="mySecret")

class SetSecretResponse(BaseModel):
    message: str = Field(..., example="Secret has been set successfully")

class GetSecretResponse(BaseModel):
    secret: str = Field(..., example="The secret associated with the provided details")

# =========================
# Utility and Auth Functions
# =========================

def create_access_token(subject: str, uid: int, email: str, expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.now(tz=timezone.utc) + (expires_delta or timedelta(hours=1))
    payload = {
        "sub": subject,
        "uid": uid,
        "email": email,
        "jti": secrets.token_urlsafe(8),
        "iat": int(datetime.now(tz=timezone.utc).timestamp()),
        "exp": int(expire.timestamp()),
        "typ": "access",
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        decoded = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return decoded
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

def extract_bearer_token(request: Request) -> str:
    auth: str = request.headers.get("Authorization") or ""
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    return auth.split(" ", 1)[1].strip()

async def get_current_user(request: Request, conn: sqlite3.Connection = Depends(get_db)) -> Dict[str, Any]:
    token = extract_bearer_token(request)
    payload = decode_access_token(token)
    uid = payload.get("uid")
    sub = payload.get("sub")
    if not uid or not sub:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    try:
        cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE id = ? LIMIT 1;", (uid,))
        row = cur.fetchone()
    except sqlite3.DatabaseError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    user = dict_from_row(row)
    # Ensure username in token matches the current db record
    if user.get("username") != sub:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    return user

# =========================
# Routes
# =========================

@app.post(
    "/register",
    response_model=RegisterResponse,
    responses={
        201: {"description": "Successful registration", "model": RegisterResponse},
        400: {"description": "Bad Request", "model": ErrorResponse},
    },
    status_code=status.HTTP_201_CREATED,
    summary="User registration",
    description="Register a new user with email, username and password.",
    openapi_extra={"security": []},
    tags=["Authentication"],
)
async def register(payload: RegisterRequest = Body(...), conn: sqlite3.Connection = Depends(get_db)):
    email = payload.email.strip().lower()
    username = payload.username.strip()
    password = payload.password

    if not username:
        # Invalid username
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )

    # Hash the password securely
    try:
        password_hash = pwd_context.hash(password)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )

    now_iso = datetime.now(tz=timezone.utc).isoformat()
    try:
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (email, username, password_hash, now_iso),
        )
    except sqlite3.IntegrityError:
        # Email or username uniqueness violation
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    except sqlite3.DatabaseError:
        # Generic DB failure
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    return {"message": "Registration successful"}

@app.post(
    "/login",
    response_model=LoginResponse,
    responses={
        200: {"description": "Successful login", "model": LoginResponse},
        401: {"description": "Unauthorized", "model": ErrorResponse},
    },
    summary="User login",
    description="Authenticate a user with email and password.",
    openapi_extra={"security": []},
    tags=["Authentication"],
)
async def login(payload: LoginRequest = Body(...), conn: sqlite3.Connection = Depends(get_db)):
    email = payload.email.strip().lower()
    password = payload.password

    try:
        cur = conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ? LIMIT 1;",
            (email,),
        )
        row = cur.fetchone()
    except sqlite3.DatabaseError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"},
        )

    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"},
        )

    user = dict_from_row(row)
    if not pwd_context.verify(password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"},
        )

    token = create_access_token(subject=user["username"], uid=user["id"], email=user["email"], expires_delta=timedelta(hours=1))
    return {"token": token, "message": "Login successful"}

@app.post(
    "/set_secret",
    response_model=SetSecretResponse,
    responses={
        200: {"description": "Secret set successfully", "model": SetSecretResponse},
        401: {"description": "Unauthorized", "model": ErrorResponse},
    },
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
async def set_secret(
    payload: SetSecretRequest = Body(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db),
):
    # Authorization: ensure the username in payload matches the token subject
    if payload.username != current_user.get("username"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    now_iso = datetime.now(tz=timezone.utc).isoformat()
    try:
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret_text, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret_text = excluded.secret_text,
                updated_at = excluded.updated_at;
            """,
            (current_user["id"], payload.secret, now_iso),
        )
    except sqlite3.DatabaseError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,  # keep response aligned with schema's unauthorized message
            detail={"message": "Invalid authentication token"},
        )
    return {"message": "Secret has been set successfully"}

@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
    responses={
        200: {"description": "Secret retrieved successfully", "model": GetSecretResponse},
        401: {"description": "Unauthorized", "model": ErrorResponse},
    },
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
async def get_secret(
    username: str = Query(..., example="user1"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db),
):
    # Authorization: user can only retrieve their own secret
    if username != current_user.get("username"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    try:
        cur = conn.execute(
            "SELECT secret_text FROM secrets WHERE user_id = ? LIMIT 1;",
            (current_user["id"],),
        )
        row = cur.fetchone()
    except sqlite3.DatabaseError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    secret_text = row["secret_text"] if row and row["secret_text"] is not None else ""
    return {"secret": secret_text}

# =========================
# Global Error Handling
# =========================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Ensure detail is a dict with message to comply with schema samples
    if isinstance(exc.detail, dict):
        return JSONResponse(status_code=exc.status_code, content=exc.detail)
    else:
        return JSONResponse(status_code=exc.status_code, content={"message": str(exc.detail)})

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Do not leak internal errors; provide generic 500 message
    return JSONResponse(status_code=500, content={"message": "Internal server error"})

# =========================
# OpenAPI Customization
# =========================

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=APP_TITLE,
        version=APP_VERSION,
        description=APP_DESCRIPTION,
        routes=app.routes,
    )
    components = openapi_schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Global security requirement as per provided schema
    openapi_schema["security"] = [{"bearerAuth": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# =========================
# Main entry point
# =========================

if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)