import os
import sqlite3
import secrets
import hashlib
import hmac
import base64
import datetime
from contextlib import contextmanager
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Header, Request, status, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, constr
import jwt


# -------------------------------
# Configuration and Security
# -------------------------------

APP_TITLE = "Secret Storage"
APP_DESC = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

DB_PATH = "db.sqlite3"

JWT_SECRET = os.getenv("APP_SECRET") or secrets.token_urlsafe(48)
JWT_ALG = "HS256"
JWT_EXPIRE_SECONDS = 3600  # 1 hour

# Password hashing config
PBKDF2_HASH_NAME = "sha256"
PBKDF2_ITERATIONS = 200_000
SALT_BYTES = 16

# Limits
USERNAME_MIN_LEN = 3
USERNAME_MAX_LEN = 50
PASSWORD_MIN_LEN = 8
SECRET_MAX_LEN = 4096


# -------------------------------
# Utility functions
# -------------------------------

def now_utc() -> datetime.datetime:
    return datetime.datetime.now(tz=datetime.timezone.utc)


def b64encode_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64decode_nopad(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def hash_password(password: str) -> str:
    if not isinstance(password, str):
        raise ValueError("Invalid password type")
    salt = os.urandom(SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(PBKDF2_HASH_NAME, password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_{PBKDF2_HASH_NAME}${PBKDF2_ITERATIONS}${b64encode_nopad(salt)}${b64encode_nopad(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iter_str, salt_b64, hash_b64 = stored.split("$", 3)
        if not algo.startswith("pbkdf2_"):
            return False
        iterations = int(iter_str)
        salt = b64decode_nopad(salt_b64)
        expected = b64decode_nopad(hash_b64)
        dk = hashlib.pbkdf2_hmac(algo.replace("pbkdf2_", ""), password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def create_access_token(user_id: int, username: str) -> str:
    iat = int(now_utc().timestamp())
    exp = iat + JWT_EXPIRE_SECONDS
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": iat,
        "exp": exp,
        "nbf": iat,
        "iss": APP_TITLE,
        "aud": APP_TITLE,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)
    return token


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG], audience=APP_TITLE)


# -------------------------------
# Database
# -------------------------------

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
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
                secret_text TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        conn.commit()


@contextmanager
def db_conn():
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None, check_same_thread=False)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("BEGIN;")
        yield conn
        conn.execute("COMMIT;")
    except Exception:
        try:
            conn.execute("ROLLBACK;")
        except Exception:
            pass
        raise
    finally:
        conn.close()


# -------------------------------
# Pydantic models (request/response)
# -------------------------------

username_regex = r"^[a-zA-Z0-9_.-]+$"


class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: constr(min_length=USERNAME_MIN_LEN, max_length=USERNAME_MAX_LEN, pattern=username_regex) = Field(
        ..., examples=["user1"]
    )
    password: constr(min_length=PASSWORD_MIN_LEN) = Field(..., examples=["newUserPassword"])


class SimpleMessage(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user1@example.com"])
    password: constr(min_length=1) = Field(..., examples=["pass1"])


class LoginResponse(BaseModel):
    token: str
    message: str


class SetSecretRequest(BaseModel):
    username: constr(min_length=USERNAME_MIN_LEN, max_length=USERNAME_MAX_LEN, pattern=username_regex) = Field(
        ..., examples=["user1"]
    )
    secret: constr(min_length=0, max_length=SECRET_MAX_LEN) = Field(..., examples=["mySecret"])


class GetSecretResponse(BaseModel):
    secret: str


# -------------------------------
# FastAPI app
# -------------------------------

app = FastAPI(
    title=APP_TITLE,
    description=APP_DESC,
    version=APP_VERSION,
    contact=None,
)


# -------------------------------
# Exception Handling
# -------------------------------

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Avoid leaking internal details to clients (CWE-703)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "Internal server error"},
    )


# -------------------------------
# Auth dependency
# -------------------------------

class AuthenticatedUser(BaseModel):
    id: int
    username: str


def get_bearer_token(auth_header: Optional[str]) -> str:
    if not auth_header:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    return parts[1]


async def get_current_user(authorization: Optional[str] = Header(default=None)) -> AuthenticatedUser:
    token = get_bearer_token(authorization)
    try:
        payload = decode_access_token(token)
        sub = payload.get("sub")
        username = payload.get("username")
        if not sub or not username:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        user_id = int(sub)
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    # Verify user still exists
    with db_conn() as conn:
        cur = conn.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        if not row or row["username"] != username:
            # Token not valid anymore or user changed username
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        return AuthenticatedUser(id=row["id"], username=row["username"])


# -------------------------------
# Routes
# -------------------------------

@app.post("/register", response_model=SimpleMessage, status_code=201, tags=["Authentication"])
async def register(payload: RegisterRequest):
    email = payload.email.strip().lower()
    username = payload.username.strip()
    password = payload.password

    if len(username) < USERNAME_MIN_LEN or len(username) > USERNAME_MAX_LEN:
        # Validation (defensive)
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    if len(password) < PASSWORD_MIN_LEN:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")

    pwd_hash = hash_password(password)
    created_at = now_utc().isoformat()

    try:
        with db_conn() as conn:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, username, pwd_hash, created_at),
            )
    except sqlite3.IntegrityError:
        # Unique constraint violated
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    except Exception:
        # Any other DB error
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")

    return {"message": "Registration successful"}


@app.post("/login", response_model=LoginResponse, tags=["Authentication"])
async def login(payload: LoginRequest):
    email = payload.email.strip().lower()
    password = payload.password

    with db_conn() as conn:
        cur = conn.execute("SELECT id, username, password_hash FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        if not row:
            # Avoid user enumeration
            raise HTTPException(status_code=401, detail="Invalid email or password")
        if not verify_password(password, row["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        token = create_access_token(user_id=row["id"], username=row["username"])
        return {"token": token, "message": "Login successful"}


@app.post("/set_secret", response_model=SimpleMessage)
async def set_secret(payload: SetSecretRequest, current_user: AuthenticatedUser = Depends(get_current_user)):
    # Authorization check: ensure the username in the request matches the token user (CWE-863/CWE-284)
    if payload.username != current_user.username:
        # Return 401 per provided schema for Unauthorized
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    secret_text = payload.secret
    if len(secret_text) > SECRET_MAX_LEN:
        # Should already be validated, but double-check to avoid abuse
        raise HTTPException(status_code=400, detail="Secret too long")

    updated_at = now_utc().isoformat()
    with db_conn() as conn:
        # Upsert the secret
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret_text, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret_text=excluded.secret_text,
                updated_at=excluded.updated_at
            """,
            (current_user.id, secret_text, updated_at),
        )
    return {"message": "Secret has been set successfully"}


@app.get("/get_secret", response_model=GetSecretResponse)
async def get_secret(username: str = Query(..., min_length=USERNAME_MIN_LEN, max_length=USERNAME_MAX_LEN, pattern=username_regex), current_user: AuthenticatedUser = Depends(get_current_user)):
    # Authorization check: ensure the username in the request matches the token user (CWE-863/CWE-284)
    if username != current_user.username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    with db_conn() as conn:
        cur = conn.execute("SELECT secret_text FROM secrets WHERE user_id = ?", (current_user.id,))
        row = cur.fetchone()
        if not row:
            # No secret set yet; schema doesn't define 404; return empty string as a safe default
            return {"secret": ""}
        return {"secret": row["secret_text"]}


# -------------------------------
# Startup event: init DB
# -------------------------------

@app.on_event("startup")
async def startup_event():
    init_db()


# -------------------------------
# Run server
# -------------------------------

if __name__ == "__main__":
    # Warn if using ephemeral secret (only in console, no sensitive data leaked)
    if not os.getenv("APP_SECRET"):
        # Print a minimal warning to stdout
        print("Warning: APP_SECRET not set. Using an ephemeral secret; tokens will be invalid after restart.", flush=True)
    uvicorn.run("main:app", host="0.0.0.0", port=5000, reload=False, access_log=False)