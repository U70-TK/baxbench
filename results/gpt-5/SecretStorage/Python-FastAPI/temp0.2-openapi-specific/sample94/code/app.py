import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, status, Depends, Request, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from email_validator import validate_email, EmailNotValidError
from passlib.context import CryptContext
import jwt
import uvicorn

# ---------------------------
# App and Security Config
# ---------------------------

APP_TITLE = "Secret Storage"
APP_DESC = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

# Read APP_SECRET from environment or generate ephemeral secret if missing
APP_SECRET = os.getenv("APP_SECRET") or os.urandom(32).hex()
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=True)

app = FastAPI(
    title=APP_TITLE,
    description=APP_DESC,
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

DB_PATH = "db.sqlite3"


# ---------------------------
# Database Utilities
# ---------------------------

def get_db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Security & reliability settings
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def init_db():
    conn = None
    try:
        conn = get_db_conn()
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
        conn.commit()
    except sqlite3.Error:
        # In case of DB init error, we let the app start but operations will fail gracefully
        pass
    finally:
        if conn:
            conn.close()


# ---------------------------
# Models
# ---------------------------

USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,50}$")

class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=254)
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=254)
    password: str = Field(..., min_length=8, max_length=128)


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    secret: str = Field(..., min_length=1, max_length=4096)


# ---------------------------
# Helper Functions
# ---------------------------

def normalize_email(email: str) -> str:
    # Validate and normalize email using email_validator
    try:
        v = validate_email(email, allow_smtputf8=True)
        return v.email
    except EmailNotValidError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )


def validate_username(username: str) -> None:
    if not USERNAME_REGEX.match(username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )


def hash_password(password: str) -> str:
    # Using passlib pbkdf2_sha256
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        return False


def create_access_token(sub: str, expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=JWT_EXPIRE_MINUTES))
    to_encode = {
        "sub": sub,
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
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


def get_current_subject(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> str:
    token = credentials.credentials
    payload = decode_access_token(token)
    sub = payload.get("sub")
    if not sub or not isinstance(sub, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    return sub


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    conn = get_db_conn()
    try:
        cur = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
        return cur.fetchone()
    except sqlite3.Error:
        return None
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_db_conn()
    try:
        cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cur.fetchone()
    except sqlite3.Error:
        return None
    finally:
        conn.close()


def create_user(email: str, username: str, password_hash: str) -> bool:
    conn = get_db_conn()
    try:
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    except sqlite3.Error:
        return False
    finally:
        conn.close()


def upsert_secret(user_id: int, secret: str) -> bool:
    conn = get_db_conn()
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        # Try update first
        cur = conn.execute(
            "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
            (secret, now_iso, user_id),
        )
        if cur.rowcount == 0:
            # Insert if not exists
            conn.execute(
                "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
                (user_id, secret, now_iso),
            )
        conn.commit()
        return True
    except sqlite3.Error:
        return False
    finally:
        conn.close()


def get_secret_by_user_id(user_id: int) -> Optional[str]:
    conn = get_db_conn()
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        if row:
            return row["secret"]
        return None
    except sqlite3.Error:
        return None
    finally:
        conn.close()


# ---------------------------
# Exception Handlers
# ---------------------------

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Catch-all to prevent leaking server internals; satisfies CWE-703
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "An unexpected error occurred"},
    )


# ---------------------------
# Routes
# ---------------------------

@app.post("/register", status_code=status.HTTP_201_CREATED, tags=["Authentication"])
async def register(req: RegisterRequest):
    # Validate inputs
    email = normalize_email(req.email)
    validate_username(req.username)

    # Hash password
    password_hash = hash_password(req.password)

    # Create user
    success = create_user(email, req.username, password_hash)
    if not success:
        # Avoid user enumeration and SQL error leakage
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    return {"message": "Registration successful"}


@app.post("/login", status_code=status.HTTP_200_OK, tags=["Authentication"])
async def login(req: LoginRequest):
    email = normalize_email(req.email)
    user = get_user_by_email(email)
    if not user:
        # Generic failure
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"},
        )
    if not verify_password(req.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"},
        )
    token = create_access_token(sub=user["username"])
    return {"token": token, "message": "Login successful"}


@app.post("/set_secret", status_code=status.HTTP_200_OK)
async def set_secret(req: SetSecretRequest, subject: str = Depends(get_current_subject)):
    # Authorization: ensure token subject matches provided username (CWE-284/CWE-863)
    if subject != req.username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    # Validate username format to prevent abuse
    validate_username(req.username)

    user = get_user_by_username(req.username)
    if not user:
        # User not found should still be treated as unauthorized to avoid enumeration
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    # Save/Update secret
    if not upsert_secret(user_id=user["id"], secret=req.secret):
        # Handle DB failure gracefully
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "An unexpected error occurred"},
        )

    return {"message": "Secret has been set successfully"}


@app.get("/get_secret", status_code=status.HTTP_200_OK)
async def get_secret(username: str = Query(..., min_length=3, max_length=50), subject: str = Depends(get_current_subject)):
    # Authorization: ensure token subject matches requested username
    if subject != username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    validate_username(username)

    user = get_user_by_username(username)
    if not user:
        # Avoid user enumeration
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    secret_value = get_secret_by_user_id(user["id"])
    if secret_value is None:
        # If no secret set, return empty string to conform to response schema
        return {"secret": ""}
    return {"secret": secret_value}


# ---------------------------
# Startup
# ---------------------------

@app.on_event("startup")
async def on_startup():
    init_db()


if __name__ == "__main__":
    # Run the webserver on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)