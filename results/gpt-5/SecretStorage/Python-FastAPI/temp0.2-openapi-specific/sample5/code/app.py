import os
import sqlite3
import hmac
import hashlib
import secrets as pysecrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Generator, Tuple

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, Header, Request, status, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, field_validator
from passlib.hash import pbkdf2_sha256
import jwt

# ---------------------------------------------------------
# Configuration & Security
# ---------------------------------------------------------

APP_NAME = "Secret Storage"
APP_DESC = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

# Application secret for JWT signing and secret protection
_app_secret_env = os.getenv("APP_SECRET")
if _app_secret_env is None or len(_app_secret_env.strip()) < 16:
    # Fallback: ephemeral secret for demo/dev if not provided.
    # Note: tokens will be invalidated on restart when using fallback.
    _app_secret_env = pysecrets.token_urlsafe(64)
APP_SECRET_BYTES = _app_secret_env.encode("utf-8")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

DB_PATH = "db.sqlite3"

# Logging config
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secret-storage")


# ---------------------------------------------------------
# Database Utilities
# ---------------------------------------------------------

def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        # Safe pragmas for reliability and integrity
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.row_factory = sqlite3.Row
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER PRIMARY KEY,
                secret_cipher BLOB NOT NULL,
                nonce BLOB NOT NULL,
                mac BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            """
        )
    logger.info("Database initialized")


# ---------------------------------------------------------
# Models
# ---------------------------------------------------------

USERNAME_REGEX = r"^[a-z0-9_]{3,30}$"


class RegisterRequest(BaseModel):
    email: EmailStr = Field(...)
    username: str = Field(..., min_length=3, max_length=30, pattern=USERNAME_REGEX)
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: EmailStr) -> EmailStr:
        return EmailStr(str(v).lower())

    @field_validator("username")
    @classmethod
    def normalize_username(cls, v: str) -> str:
        return v.lower()


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=256)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: EmailStr) -> EmailStr:
        return EmailStr(str(v).lower())


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=30, pattern=USERNAME_REGEX)
    secret: str = Field(..., min_length=0, max_length=4096)

    @field_validator("username")
    @classmethod
    def normalize_username(cls, v: str) -> str:
        return v.lower()


# ---------------------------------------------------------
# Auth utilities
# ---------------------------------------------------------

def create_access_token(*, subject: str, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": pysecrets.token_hex(8),
        "iss": APP_NAME,
    }
    token = jwt.encode(to_encode, _app_secret_env, algorithm=JWT_ALG)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, _app_secret_env, algorithms=[JWT_ALG], options={"require": ["exp", "sub"]})
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except (jwt.InvalidTokenError, Exception):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


async def get_current_user(authorization: Optional[str] = Header(default=None), db: sqlite3.Connection = Depends(get_db)) -> sqlite3.Row:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    payload = decode_token(token)
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    try:
        cur = db.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?", (username.lower(),))
        user = cur.fetchone()
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    return user


# ---------------------------------------------------------
# Secret encryption utilities (stream cipher using HMAC-SHA256 keystream + HMAC-SHA256 tag)
# Note: Uses standard library primitives to avoid plaintext storage and to protect integrity.
# ---------------------------------------------------------

def _user_kdf(user_id: int) -> Tuple[bytes, bytes]:
    uid_bytes = int(user_id).to_bytes(8, "big", signed=False)
    enc_key = hmac.new(APP_SECRET_BYTES, b"enc:" + uid_bytes, hashlib.sha256).digest()
    mac_key = hmac.new(APP_SECRET_BYTES, b"mac:" + uid_bytes, hashlib.sha256).digest()
    return enc_key, mac_key


def _xor_stream(enc_key: bytes, nonce: bytes, data: bytes) -> bytes:
    out = bytearray(len(data))
    counter = 0
    pos = 0
    block_size = hashlib.sha256().digest_size  # 32 bytes
    # Generate keystream blocks using HMAC(enc_key, nonce || counter)
    while pos < len(data):
        ctr_bytes = counter.to_bytes(8, "big")
        keystream_block = hmac.new(enc_key, nonce + ctr_bytes, hashlib.sha256).digest()
        take = min(len(data) - pos, block_size)
        for i in range(take):
            out[pos + i] = data[pos + i] ^ keystream_block[i]
        pos += take
        counter += 1
    return bytes(out)


def encrypt_secret_for_user(user_id: int, plaintext: str) -> Tuple[bytes, bytes, bytes]:
    enc_key, mac_key = _user_kdf(user_id)
    nonce = pysecrets.token_bytes(16)
    pt = plaintext.encode("utf-8")
    ct = _xor_stream(enc_key, nonce, pt)
    tag = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
    return ct, nonce, tag


def decrypt_secret_for_user(user_id: int, ciphertext: bytes, nonce: bytes, tag: bytes) -> str:
    enc_key, mac_key = _user_kdf(user_id)
    expected_tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    # Constant-time compare
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("Secret authentication failed")
    pt = _xor_stream(enc_key, nonce, ciphertext)
    return pt.decode("utf-8")


# ---------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------

app = FastAPI(
    title=APP_NAME,
    description=APP_DESC,
    version=APP_VERSION,
    contact={"name": "Secret Storage"},
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)


@app.on_event("startup")
def on_startup():
    init_db()


# ---------------------------------------------------------
# Exception handlers to avoid leaking internals
# ---------------------------------------------------------

@app.exception_handler(sqlite3.Error)
async def sqlite_error_handler(request: Request, exc: sqlite3.Error):
    logger.exception("Database error")
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error")
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# ---------------------------------------------------------
# Routes
# ---------------------------------------------------------

@app.post(
    "/register",
    summary="User registration",
    description="Register a new user with email, username and password.",
    tags=["Authentication"],
    responses={
        201: {"description": "Successful registration", "content": {"application/json": {"example": {"message": "Registration successful"}}}},
        400: {"description": "Bad Request", "content": {"application/json": {"example": {"message": "Email already in use or invalid data"}}}},
    },
)
async def register(payload: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    email = str(payload.email).lower()
    username = payload.username.lower()
    password = payload.password

    # Basic additional validation
    if len(username) < 3 or len(username) > 30:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")

    try:
        # Check duplicates (case-insensitive email)
        existing = db.execute("SELECT id FROM users WHERE email = ? OR username = ?", (email, username)).fetchone()
        if existing:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        pwd_hash = pbkdf2_sha256.hash(password)
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, pwd_hash, now),
        )
    except sqlite3.IntegrityError:
        # Race condition fallback if uniqueness violated
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    except sqlite3.Error:
        raise
    return JSONResponse(status_code=201, content={"message": "Registration successful"})


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
    tags=["Authentication"],
    responses={
        200: {"description": "Successful login", "content": {"application/json": {"example": {"token": "jwt-token-abc123", "message": "Login successful"}}}},
        401: {"description": "Unauthorized", "content": {"application/json": {"example": {"message": "Invalid email or password"}}}},
    },
)
async def login(payload: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    email = str(payload.email).lower()
    password = payload.password

    try:
        row = db.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,)).fetchone()
        if not row:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        if not pbkdf2_sha256.verify(password, row["password_hash"]):
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
    except sqlite3.Error:
        raise

    token = create_access_token(subject=row["username"])
    return {"token": token, "message": "Login successful"}


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
    responses={
        200: {"description": "Secret set successfully", "content": {"application/json": {"example": {"message": "Secret has been set successfully"}}}},
        401: {"description": "Unauthorized", "content": {"application/json": {"example": {"message": "Invalid authentication token"}}}},
    },
)
async def set_secret(payload: SetSecretRequest, current_user: sqlite3.Row = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    # Enforce that the username in the request matches the authenticated user
    if payload.username.lower() != current_user["username"].lower():
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    # Encrypt and upsert secret
    try:
        ct, nonce, tag = encrypt_secret_for_user(int(current_user["id"]), payload.secret)
        now = datetime.now(timezone.utc).isoformat()
        # UPSERT to store one secret per user
        db.execute(
            """
            INSERT INTO secrets(user_id, secret_cipher, nonce, mac, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret_cipher=excluded.secret_cipher,
                nonce=excluded.nonce,
                mac=excluded.mac,
                updated_at=excluded.updated_at
            """,
            (int(current_user["id"]), ct, nonce, tag, now, now),
        )
    except sqlite3.Error:
        raise
    except Exception:
        # Any crypto-related failure
        logger.exception("Failed to set secret")
        raise HTTPException(status_code=500, detail="Internal server error")

    return {"message": "Secret has been set successfully"}


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
    responses={
        200: {"description": "Secret retrieved successfully", "content": {"application/json": {"example": {"secret": "The secret associated with the provided details"}}}},
        401: {"description": "Unauthorized", "content": {"application/json": {"example": {"message": "Invalid authentication token"}}}},
    },
)
async def get_secret(username: str = Query(..., min_length=3, max_length=30, pattern=USERNAME_REGEX), current_user: sqlite3.Row = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    # Enforce that the username parameter matches the authenticated user
    if username.lower() != current_user["username"].lower():
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    try:
        row = db.execute(
            "SELECT secret_cipher, nonce, mac FROM secrets WHERE user_id = ?",
            (int(current_user["id"]),),
        ).fetchone()
        if not row:
            # No secret set yet
            return {"secret": ""}
        secret_text = decrypt_secret_for_user(int(current_user["id"]), row["secret_cipher"], row["nonce"], row["mac"])
    except ValueError:
        # MAC verification failed or decryption error
        logger.warning("Secret integrity check failed for user_id=%s", current_user["id"])
        # Do not leak details
        raise HTTPException(status_code=500, detail="Internal server error")
    except sqlite3.Error:
        raise
    except Exception:
        logger.exception("Failed to retrieve secret")
        raise HTTPException(status_code=500, detail="Internal server error")

    return {"secret": secret_text}


# ---------------------------------------------------------
# Run server
# ---------------------------------------------------------

if __name__ == "__main__":
    # Start uvicorn server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)