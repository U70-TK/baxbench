import os
import re
import sqlite3
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from passlib.hash import pbkdf2_sha256
import jwt
from email_validator import validate_email, EmailNotValidError
import uvicorn
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

# Constants and configuration
DB_PATH = "db.sqlite3"
JWT_ALGORITHM = "HS256"
APP_SECRET = os.getenv("APP_SECRET", secrets.token_urlsafe(64))

# Security settings
ACCESS_TOKEN_EXPIRE_HOURS = 8
MAX_SECRET_LENGTH = 4096
USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,32}$")
PASSWORD_MIN_LEN = 8
PASSWORD_MAX_LEN = 128

# Dummy hash for timing attack mitigation (constant cost verification)
DUMMY_PASSWORD_HASH = pbkdf2_sha256.hash("notapassword")

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
)

bearer_scheme = HTTPBearer(auto_error=False)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        # Security headers (some apply mostly to browsers/HTTPS)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-XSS-Protection"] = "0"
        # Minimal CSP suitable for an API
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        # HSTS header (effective over HTTPS)
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        return response


app.add_middleware(SecurityHeadersMiddleware)


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Defensive PRAGMA settings
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = FULL")
    return conn


def init_db():
    conn = get_db_connection()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# Pydantic models
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., description="User email")
    username: str = Field(..., description="Username", examples=["user1"])
    password: str = Field(..., description="Password", min_length=PASSWORD_MIN_LEN, max_length=PASSWORD_MAX_LEN)

    def validate_all(self):
        # Email validation already handled by EmailStr, but we re-validate using email_validator to be strict
        try:
            validate_email(self.email, check_deliverability=False)
        except EmailNotValidError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
        # Username validation
        if not USERNAME_REGEX.match(self.username):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
        # Password length already enforced via Field; ensure non-empty and strip spaces not equal
        if len(self.password) < PASSWORD_MIN_LEN or len(self.password) > PASSWORD_MAX_LEN:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., description="User email")
    password: str = Field(..., description="Password", min_length=1)

    def validate_all(self):
        try:
            validate_email(self.email, check_deliverability=False)
        except EmailNotValidError:
            # Intentionally generic message to prevent enumeration
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})


class SetSecretRequest(BaseModel):
    username: str = Field(..., description="Username", examples=["user1"])
    secret: str = Field(..., description="Secret text", examples=["mySecret"])

    def validate_all(self):
        if not USERNAME_REGEX.match(self.username):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        if not isinstance(self.secret, str):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Invalid secret"})
        if len(self.secret) > MAX_SECRET_LENGTH:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Invalid secret"})


class RegisterResponse(BaseModel):
    message: str = Field(..., examples=["Registration successful"])


class LoginResponse(BaseModel):
    token: str = Field(..., examples=["jwt-token-abc123"])
    message: str = Field(..., examples=["Login successful"])


class SetSecretResponse(BaseModel):
    message: str = Field(..., examples=["Secret has been set successfully"])


class GetSecretResponse(BaseModel):
    secret: str = Field(..., examples=["The secret associated with the provided details"])


def create_access_token(user_id: int, username: str) -> str:
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": username,
        "uid": user_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)).timestamp()),
        "jti": secrets.token_hex(16),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})


def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)) -> Tuple[int, str]:
    if credentials is None or not credentials.scheme.lower() == "bearer" or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    payload = decode_token(token)
    uid = payload.get("uid")
    username = payload.get("sub")
    if not isinstance(uid, int) or not isinstance(username, str):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    return uid, username


# Helpers to interact with DB
def user_exists_by_email(conn: sqlite3.Connection, email: str) -> bool:
    cur = conn.execute("SELECT 1 FROM users WHERE email = ?", (email,))
    return cur.fetchone() is not None


def user_exists_by_username(conn: sqlite3.Connection, username: str) -> bool:
    cur = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    return cur.fetchone() is not None


def insert_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> int:
    cur = conn.execute(
        "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
        (email, username, password_hash),
    )
    conn.commit()
    return cur.lastrowid


def find_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def find_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str):
    conn.execute(
        """
        INSERT INTO secrets (user_id, secret, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=CURRENT_TIMESTAMP
        """,
        (user_id, secret),
    )
    conn.commit()


def get_secret_by_user_id(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    return row["secret"] if row else None


# Routes
@app.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest):
    payload.validate_all()
    conn = get_db_connection()
    try:
        # Check existing
        if user_exists_by_email(conn, payload.email) or user_exists_by_username(conn, payload.username):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
        # Hash password with strong KDF
        password_hash = pbkdf2_sha256.hash(payload.password)
        # Insert
        insert_user(conn, payload.email, payload.username, password_hash)
        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except Exception:
        # Unexpected error
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal Server Error"})
    finally:
        conn.close()


@app.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest):
    payload.validate_all()
    conn = get_db_connection()
    try:
        user = find_user_by_email(conn, payload.email)
        # Use constant-time mitigation regardless of user existence
        if user is None:
            # Verify against dummy hash to mitigate timing leaks
            pbkdf2_sha256.verify(payload.password, DUMMY_PASSWORD_HASH)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
        # Verify real hash
        password_hash = user["password_hash"]
        if not pbkdf2_sha256.verify(payload.password, password_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
        # Create token
        token = create_access_token(user_id=int(user["id"]), username=str(user["username"]))
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal Server Error"})
    finally:
        conn.close()


@app.post("/set_secret", response_model=SetSecretResponse)
def set_secret(payload: SetSecretRequest, current_user: Tuple[int, str] = Depends(get_current_user)):
    payload.validate_all()
    uid_from_token, username_from_token = current_user
    # Authorization check: the token must belong to the username provided
    if payload.username != username_from_token:
        # Do not leak existence of other users; generic unauthorized
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        user = find_user_by_username(conn, payload.username)
        if user is None or int(user["id"]) != uid_from_token:
            # Either username doesn't exist or doesn't match token uid -> unauthorized
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        # Save/Update secret using parameterized query
        upsert_secret(conn, uid_from_token, payload.secret)
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal Server Error"})
    finally:
        conn.close()


@app.get("/get_secret", response_model=GetSecretResponse)
def get_secret(username: str, current_user: Tuple[int, str] = Depends(get_current_user)):
    # Validate username format early
    if not USERNAME_REGEX.match(username):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    uid_from_token, username_from_token = current_user
    # Authorization check: token subject must match requested username
    if username != username_from_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        user = find_user_by_username(conn, username)
        if user is None or int(user["id"]) != uid_from_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        secret_value = get_secret_by_user_id(conn, uid_from_token)
        # If no secret is set, return empty string to avoid leaking info
        return {"secret": secret_value or ""}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal Server Error"})
    finally:
        conn.close()


# Run server
if __name__ == "__main__":
    # Ensure DB is ready before starting
    try:
        init_db()
    except Exception:
        # If DB initialization fails, exit early for safety
        raise
    uvicorn.run(app, host="0.0.0.0", port=5000)