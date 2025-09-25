import os
import sqlite3
import hmac
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt  # pyjwt
from fastapi import FastAPI, Depends, Request
from fastapi import status
from fastapi.exceptions import RequestValidationError
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from starlette.responses import JSONResponse
import uvicorn

# ------------------------------------------------------------------------------
# Configuration & Security
# ------------------------------------------------------------------------------

APP_NAME = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

DB_PATH = "db.sqlite3"

# Application secret for JWT
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback for development/testing. In production, APP_SECRET must be set.
    APP_SECRET = os.urandom(32).hex()
    logging.warning("APP_SECRET env variable not set; using a generated ephemeral secret. Set APP_SECRET for production.")

JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60  # Token validity

# Password hashing (no external bcrypt dependency, use strong PBKDF2)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# HTTP Bearer auth dependency
security = HTTPBearer(auto_error=False)

# ------------------------------------------------------------------------------
# Database Utilities
# ------------------------------------------------------------------------------

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Ensure foreign key constraints are enforced
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db_connection()
    try:
        # Create tables with proper constraints
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            secret TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)
        conn.commit()
    except sqlite3.Error as e:
        # Log server-side but avoid leaking implementation details
        logging.error(f"Database initialization failed: {e}")
        raise
    finally:
        conn.close()

def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
        return cur.fetchone()
    except sqlite3.Error as e:
        logging.error(f"DB error get_user_by_email: {e}")
        return None
    finally:
        conn.close()

def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username FROM users WHERE username = ?", (username,))
        return cur.fetchone()
    except sqlite3.Error as e:
        logging.error(f"DB error get_user_by_username: {e}")
        return None
    finally:
        conn.close()

def create_user(email: str, username: str, password_hash: str) -> bool:
    conn = get_db_connection()
    try:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, now),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # Unique constraint violation or invalid data
        return False
    except sqlite3.Error as e:
        logging.error(f"DB error create_user: {e}")
        return False
    finally:
        conn.close()

def upsert_secret(user_id: int, secret: str) -> bool:
    conn = get_db_connection()
    try:
        now = datetime.now(timezone.utc).isoformat()
        # UPSERT on user_id
        conn.execute("""
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret = excluded.secret,
                updated_at = excluded.updated_at
        """, (user_id, secret, now))
        conn.commit()
        return True
    except sqlite3.Error as e:
        logging.error(f"DB error upsert_secret: {e}")
        return False
    finally:
        conn.close()

def get_secret_by_user_id(user_id: int) -> Optional[str]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        return row["secret"] if row else None
    except sqlite3.Error as e:
        logging.error(f"DB error get_secret_by_user_id: {e}")
        return None
    finally:
        conn.close()

# ------------------------------------------------------------------------------
# JWT Utilities
# ------------------------------------------------------------------------------

def create_access_token(uid: int, username: str, expires_minutes: int = JWT_EXPIRE_MINUTES) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    to_encode = {"uid": uid, "username": username, "exp": expire, "iat": datetime.now(timezone.utc)}
    token = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        # Unauthorized if token missing or wrong scheme
        raise_http_unauthorized()
    payload = decode_token(credentials.credentials)
    if not payload:
        raise_http_unauthorized()
    uid = payload.get("uid")
    uname = payload.get("username")
    if not uid or not uname:
        raise_http_unauthorized()
    # Verify user exists and matches token claims to avoid CWE-863
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username FROM users WHERE id = ?", (uid,))
        row = cur.fetchone()
        if not row or not hmac.compare_digest(row["username"], uname):
            raise_http_unauthorized()
        return {"id": row["id"], "email": row["email"], "username": row["username"]}
    finally:
        conn.close()

def raise_http_unauthorized():
    # Centralized unauthorized response to match schema
    # Use message field per schema
    from fastapi import HTTPException
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

# ------------------------------------------------------------------------------
# Pydantic Schemas
# ------------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=6, max_length=128)

class RegisterResponse(BaseModel):
    message: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

class LoginResponse(BaseModel):
    token: str
    message: str

class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    secret: str = Field(min_length=1)

class SetSecretResponse(BaseModel):
    message: str

class GetSecretResponse(BaseModel):
    secret: str

# ------------------------------------------------------------------------------
# FastAPI App and Exception Handlers
# ------------------------------------------------------------------------------

app = FastAPI(
    title=APP_NAME,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

@app.on_event("startup")
def on_startup():
    try:
        init_db()
    except Exception as e:
        # Failing fast if DB cannot be initialized to satisfy CWE-703
        logging.critical(f"Failed to initialize database: {e}")
        raise

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Map validation errors to schema-specified messages
    path = request.url.path
    if path == "/register":
        message = "Email already in use or invalid data"
        status_code = status.HTTP_400_BAD_REQUEST
    else:
        message = "Invalid input data"
        status_code = status.HTTP_400_BAD_REQUEST
    return JSONResponse(status_code=status_code, content={"message": message})

from fastapi import HTTPException

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Convert FastAPI HTTPException detail to {"message": "..."} per schema
    detail = exc.detail
    if isinstance(detail, dict) and "message" in detail:
        message = detail["message"]
    elif isinstance(detail, str):
        message = detail
    else:
        message = "An error occurred"
    return JSONResponse(status_code=exc.status_code, content={"message": message})

# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@app.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED, tags=["Authentication"])
async def register(payload: RegisterRequest):
    # Validate email (pydantic EmailStr already validates), enforce uniqueness
    try:
        # Check for existing email or username
        existing_by_email = get_user_by_email(payload.email)
        if existing_by_email is not None:
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"message": "Email already in use or invalid data"})

        existing_by_username = get_user_by_username(payload.username)
        if existing_by_username is not None:
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"message": "Email already in use or invalid data"})

        password_hash = pwd_context.hash(payload.password)
        created = create_user(email=payload.email, username=payload.username, password_hash=password_hash)
        if not created:
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"message": "Email already in use or invalid data"})
        return {"message": "Registration successful"}
    except Exception as e:
        logging.error(f"Unexpected error in /register: {e}")
        # General error handling for CWE-703
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"message": "Internal server error"})

@app.post("/login", response_model=LoginResponse, tags=["Authentication"])
async def login(payload: LoginRequest):
    try:
        user = get_user_by_email(payload.email)
        # Do not reveal whether email exists; generic error on failure (CWE-522 user enumeration)
        if user is None:
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})
        if not pwd_context.verify(payload.password, user["password_hash"]):
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})

        token = create_access_token(uid=user["id"], username=user["username"])
        return {"token": token, "message": "Login successful"}
    except Exception as e:
        logging.error(f"Unexpected error in /login: {e}")
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"message": "Internal server error"})

@app.post("/set_secret", response_model=SetSecretResponse)
async def set_secret(payload: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    try:
        # Authorization check: ensure the username in the body matches the token subject to prevent CWE-863
        if not hmac.compare_digest(current_user["username"], payload.username):
            # Do not leak details; respond with invalid token per schema
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

        success = upsert_secret(user_id=current_user["id"], secret=payload.secret)
        if not success:
            # Database error
            return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"message": "Internal server error"})
        return {"message": "Secret has been set successfully"}
    except Exception as e:
        logging.error(f"Unexpected error in /set_secret: {e}")
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"message": "Internal server error"})

@app.get("/get_secret", response_model=GetSecretResponse)
async def get_secret(username: str, current_user: dict = Depends(get_current_user)):
    try:
        # Authorization check: ensure the username in the query matches the token subject
        if not hmac.compare_digest(current_user["username"], username):
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})
        # Retrieve secret; if none, return empty string to conform to schema
        secret = get_secret_by_user_id(current_user["id"])
        return {"secret": secret if secret is not None else ""}
    except Exception as e:
        logging.error(f"Unexpected error in /get_secret: {e}")
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"message": "Internal server error"})

# ------------------------------------------------------------------------------
# Run Server
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    # Start server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)