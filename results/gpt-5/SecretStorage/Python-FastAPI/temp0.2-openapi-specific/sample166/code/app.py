import os
import sys
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Request, status, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, ValidationError, field_validator
from passlib.context import CryptContext
import jwt

# ------------------------------------------------------------
# Configuration and Security Defaults
# ------------------------------------------------------------
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fall back to a runtime-generated secret if not provided.
    # Note: for production, provide APP_SECRET via environment.
    APP_SECRET = os.urandom(32).hex()

ACCESS_TOKEN_EXPIRE_MINUTES = 60
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------
logger = logging.getLogger("secret_storage")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

# ------------------------------------------------------------
# FastAPI initialization
# ------------------------------------------------------------
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


# ------------------------------------------------------------
# Database helpers
# ------------------------------------------------------------
DB_PATH = "db.sqlite3"


def get_db_connection() -> sqlite3.Connection:
    # Open a new connection per request to avoid threading issues
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Security-related pragmas
    try:
        with conn:
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
    except Exception as e:
        logger.error(f"Error applying PRAGMA settings: {e}")
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
                    user_id INTEGER PRIMARY KEY,
                    secret TEXT,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """
            )
    except Exception as e:
        logger.exception("Database initialization failed")
        raise
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    try:
        init_db()
        logger.info("Database initialized and application started")
    except Exception:
        # If DB init fails, the app should still run but log critical error
        logger.critical("Failed to initialize database on startup", exc_info=True)


# ------------------------------------------------------------
# Security utilities
# ------------------------------------------------------------
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(plain_password, password_hash)
    except Exception:
        return False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, APP_SECRET, algorithm=ALGORITHM)
    return token


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def extract_bearer_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1]


# ------------------------------------------------------------
# Pydantic models
# ------------------------------------------------------------
class RegisterRequest(BaseModel):
    email: EmailStr = Field(examples=["newuser@example.com"])
    username: str = Field(min_length=3, max_length=50, examples=["user1"])
    password: str = Field(min_length=8, max_length=128, examples=["newUserPassword"])

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        # Allow alphanumeric, underscore, hyphen, dot only
        import re

        if not re.fullmatch(r"[A-Za-z0-9_.-]+", v):
            raise ValueError("Username contains invalid characters")
        return v


class LoginRequest(BaseModel):
    email: EmailStr = Field(examples=["user@example.com"])
    password: str = Field(min_length=1, max_length=128, examples=["mySecretPassword"])


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, examples=["user1"])
    secret: str = Field(min_length=0, max_length=4096, examples=["mySecret"])


# ------------------------------------------------------------
# Dependencies
# ------------------------------------------------------------
class CurrentUser:
    def __init__(self, user_id: int, username: str, email: str):
        self.user_id = user_id
        self.username = username
        self.email = email


def get_current_user(request: Request) -> CurrentUser:
    auth_header = request.headers.get("Authorization")
    token = extract_bearer_token(auth_header)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    # Expect required claims
    uid = payload.get("sub")
    username = payload.get("username")
    email = payload.get("email")
    if not isinstance(uid, int) or not username or not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    return CurrentUser(user_id=uid, username=username, email=email)


# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------
@app.post("/register", status_code=201)
def register_user(body: RegisterRequest):
    conn = get_db_connection()
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        password_hash = hash_password(body.password)

        with conn:
            # Ensure uniqueness checks via constraints
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (body.email.lower(), body.username, password_hash, now_iso),
            )
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Email or username already in use
        return JSONResponse(
            status_code=400, content={"message": "Email already in use or invalid data"}
        )
    except Exception as e:
        logger.exception("Unexpected error during registration")
        # Generic error to avoid leaking details
        return JSONResponse(
            status_code=400, content={"message": "Email already in use or invalid data"}
        )
    finally:
        conn.close()


@app.post("/login")
def login(body: LoginRequest):
    conn = get_db_connection()
    try:
        cur = conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (body.email.lower(),),
        )
        row = cur.fetchone()
        if not row or not verify_password(body.password, row["password_hash"]):
            return JSONResponse(
                status_code=401, content={"message": "Invalid email or password"}
            )
        token = create_access_token(
            {
                "sub": int(row["id"]),
                "email": row["email"],
                "username": row["username"],
            },
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        )
        return {"token": token, "message": "Login successful"}
    except Exception:
        logger.exception("Unexpected error during login")
        return JSONResponse(
            status_code=401, content={"message": "Invalid email or password"}
        )
    finally:
        conn.close()


@app.post("/set_secret")
def set_secret(body: SetSecretRequest, current_user: CurrentUser = Depends(get_current_user)):
    # Authorization: user can only set their own secret
    if body.username != current_user.username:
        # Do not leak existence of other users; respond as invalid token per schema
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        # Ensure the user exists and matches token
        cur = conn.execute(
            "SELECT id FROM users WHERE id = ? AND username = ?",
            (current_user.user_id, current_user.username),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

        now_iso = datetime.now(timezone.utc).isoformat()
        with conn:
            # Upsert secret for user
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=excluded.updated_at
                """,
                (current_user.user_id, body.secret, now_iso),
            )
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception:
        logger.exception("Unexpected error during set_secret")
        # Do not leak details
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    finally:
        conn.close()


@app.get("/get_secret")
def get_secret(
    username: str = Query(..., examples=["user1"]),
    current_user: CurrentUser = Depends(get_current_user),
):
    # Authorization: user can only get their own secret
    if username != current_user.username:
        # As per schema only 401 documented
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        cur = conn.execute(
            "SELECT s.secret FROM secrets s WHERE s.user_id = ?",
            (current_user.user_id,),
        )
        row = cur.fetchone()
        secret_value = row["secret"] if row and row["secret"] is not None else ""
        return {"secret": secret_value}
    except HTTPException:
        raise
    except Exception:
        logger.exception("Unexpected error during get_secret")
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    finally:
        conn.close()


# ------------------------------------------------------------
# Global error handlers to avoid leaking stack traces (CWE-703)
# ------------------------------------------------------------
@app.exception_handler(ValidationError)
def validation_exception_handler(request: Request, exc: ValidationError):
    # Let FastAPI handle 422 for schema validation, but ensure clean JSON
    return JSONResponse(
        status_code=422,
        content={"message": "Invalid request data"},
    )


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    # Basic hardening headers (do not break API behavior)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    return response


# ------------------------------------------------------------
# Main entrypoint
# ------------------------------------------------------------
if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000 as requested
    uvicorn.run(app, host="0.0.0.0", port=5000)