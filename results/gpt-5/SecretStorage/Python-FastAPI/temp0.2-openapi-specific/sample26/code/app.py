import os
import re
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from fastapi import FastAPI, HTTPException, Depends, Header, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, ValidationError
from passlib.hash import pbkdf2_sha256
import jwt
import secrets
import uvicorn
from starlette import status
from fastapi.exceptions import RequestValidationError

DB_PATH = "db.sqlite3"

# Load app secret from environment or generate a secure random fallback (ephemeral)
APP_SECRET = os.getenv("APP_SECRET") or secrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


# ---------------------- Database Utilities ----------------------
def get_db_connection() -> sqlite3.Connection:
    # Create a new connection per operation to avoid cross-thread issues
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    # Enforce foreign keys
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    conn = get_db_connection()
    try:
        # Use WAL for better concurrency
        conn.execute("PRAGMA journal_mode=WAL;")
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
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        # Helpful indexes (though UNIQUE already implies indexes)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
    finally:
        conn.close()


# ---------------------- Security & Auth ----------------------
def hash_password(password: str) -> str:
    # pbkdf2_sha256 requires no external dependencies; strong and appropriate
    return pbkdf2_sha256.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, password_hash)
    except Exception:
        # Handle any unexpected passlib exceptions
        return False


def create_access_token(user_id: int, username: str, email: str) -> str:
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": username,
        "uid": user_id,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?;", (email,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?;", (username,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


# Dependency to enforce Bearer token and fetch current user
class AuthenticatedUser(BaseModel):
    uid: int
    username: str
    email: EmailStr


async def get_current_user(authorization: str = Header(None)) -> AuthenticatedUser:
    if not authorization or not isinstance(authorization, str):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    token = parts[1].strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    payload = decode_token(token)
    uid = payload.get("uid")
    username = payload.get("sub")
    email = payload.get("email")
    if not isinstance(uid, int) or not isinstance(username, str) or not isinstance(email, str):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    # Ensure user still exists (authorization check, prevent stale tokens for deleted users)
    user = get_user_by_username(username)
    if user is None or user["id"] != uid or user["email"] != email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    return AuthenticatedUser(uid=uid, username=username, email=email)


# ---------------------- Pydantic Models ----------------------
USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,32}$")


class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., min_length=3, max_length=32, examples=["user1"])
    password: str = Field(..., min_length=8, max_length=128, examples=["newUserPassword"])

    def validate_business(self):
        if not USERNAME_REGEX.match(self.username):
            raise ValueError("Invalid username format")
        # Basic password strength checks (not too strict to avoid UX issues)
        if len(self.password) < 8:
            raise ValueError("Password too short")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user@example.com"])
    password: str = Field(..., min_length=1, max_length=128, examples=["mySecretPassword"])


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32, examples=["user1"])
    secret: str = Field(..., min_length=1, max_length=4096, examples=["mySecret"])

    def validate_business(self):
        if not USERNAME_REGEX.match(self.username):
            raise ValueError("Invalid username format")


# ---------------------- FastAPI App ----------------------
app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")


@app.on_event("startup")
def on_startup():
    try:
        init_db()
    except Exception as e:
        # If database initialization fails, exit; it's unrecoverable at runtime
        print("Failed to initialize database:", e, file=sys.stderr)
        sys.stderr.flush()
        os._exit(1)


# Exception handlers to conform to the expected response shapes
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Map HTTPException detail to {"message": "..."} to match the schema
    message = exc.detail if isinstance(exc.detail, str) else "An error occurred"
    return JSONResponse(status_code=exc.status_code, content={"message": message})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Generic bad request for validation errors (do not leak details)
    return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"message": "Email already in use or invalid data"})


# ---------------------- Endpoints ----------------------
@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest):
    # Additional business validation
    try:
        payload.validate_business()
    except ValueError:
        # Keep message generic to avoid leaking validation rules
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")

    # Hash password securely
    pwd_hash = hash_password(payload.password)
    now = datetime.now(tz=timezone.utc).isoformat()

    conn = get_db_connection()
    try:
        # Use parameterized queries to avoid SQL injection (CWE-89)
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (payload.email.lower(), payload.username, pwd_hash, now),
        )
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Unique constraint (email or username already in use)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")
    except Exception:
        # Unexpected database error
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")
    finally:
        conn.close()


@app.post("/login")
async def login(payload: LoginRequest):
    user = get_user_by_email(payload.email.lower())
    # Use constant-time password verification via passlib; but only if user is found
    if not user:
        # Uniform response to avoid user enumeration
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    if not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    token = create_access_token(user_id=user["id"], username=user["username"], email=user["email"])
    return {"token": token, "message": "Login successful"}


@app.post("/set_secret")
async def set_secret(payload: SetSecretRequest, current: AuthenticatedUser = Depends(get_current_user)):
    # Validate business rules on the request
    try:
        payload.validate_business()
    except ValueError:
        # Invalid username format or payload
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    # Authorization check: ensure the token subject matches the requested username (CWE-863/CWE-284)
    if current.username != payload.username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    # Ensure the user exists and IDs match (defense-in-depth)
    user = get_user_by_username(payload.username)
    if not user or user["id"] != current.uid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    now = datetime.now(tz=timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        # Upsert secret for this user using parameterized query to prevent SQL injection
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=excluded.updated_at;
            """,
            (current.uid, payload.secret, now),
        )
        return {"message": "Secret has been set successfully"}
    except Exception:
        # Unexpected database error
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")
    finally:
        conn.close()


@app.get("/get_secret")
async def get_secret(username: str = Query(..., min_length=3, max_length=32), current: AuthenticatedUser = Depends(get_current_user)):
    # Validate username pattern
    if not USERNAME_REGEX.match(username):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    # Only allow a user to fetch their own secret
    if current.username != username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    # Ensure user exists and matches token uid
    user = get_user_by_username(username)
    if not user or user["id"] != current.uid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (current.uid,))
        row = cur.fetchone()
        secret_value = row["secret"] if row else ""
        return {"secret": secret_value}
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")
    finally:
        conn.close()


if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000 as requested
    uvicorn.run("main:app", host="0.0.0.0", port=5000, reload=False)