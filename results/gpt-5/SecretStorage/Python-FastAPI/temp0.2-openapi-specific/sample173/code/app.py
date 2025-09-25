import os
import base64
import hashlib
import hmac
import sqlite3
import time
import datetime
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Request, status, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt
import secrets as pysecrets
import uvicorn

# Application setup
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Environment and cryptographic key
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to a random secret if not provided.
    # Note: Tokens and encrypted secrets will be invalidated on restart if APP_SECRET is not set.
    APP_SECRET = base64.urlsafe_b64encode(pysecrets.token_bytes(32)).decode("utf-8")
# Derive a fixed-length binary key from APP_SECRET using SHA-256
APP_KEY = hashlib.sha256(APP_SECRET.encode("utf-8")).digest()

# Constants
JWT_ALG = "HS256"
JWT_EXP_SECONDS = 60 * 60  # 1 hour
NONCE_SIZE = 16
MAC_SIZE = 32  # SHA256 digest size
MAX_SECRET_LENGTH = 10000  # Prevent excessively large payloads


# Pydantic models
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=1, max_length=150)
    password: str = Field(min_length=1)


class MessageResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    token: str
    message: str


class SetSecretRequest(BaseModel):
    username: str
    secret: str = Field(min_length=0, max_length=MAX_SECRET_LENGTH)


class SecretResponse(BaseModel):
    secret: str


# Exception handlers to ensure response shape matches spec
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    detail = exc.detail
    if isinstance(detail, dict) and "message" in detail:
        message = detail["message"]
    elif isinstance(detail, str):
        message = detail
    else:
        message = "An error occurred"
    return JSONResponse(status_code=exc.status_code, content={"message": message})


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Handle unexpected errors gracefully (CWE-703)
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# Database helpers
def create_tables() -> None:
    try:
        with sqlite3.connect("db.sqlite3") as conn:
            conn.execute("PRAGMA foreign_keys = ON")
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
                    secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """
            )
    except Exception:
        # Fail gracefully if DB initialization fails
        raise


def get_db():
    conn = sqlite3.connect("db.sqlite3")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


create_tables()


# Crypto helpers: Encrypt-then-MAC using HMAC-SHA256-based keystream
def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    # Generate keystream using HMAC-SHA256(PRF) with nonce||counter
    blocks = []
    counter = 0
    while len(b"".join(blocks)) < length:
        counter_bytes = counter.to_bytes(4, "big")
        block = hmac.new(key, nonce + counter_bytes, hashlib.sha256).digest()
        blocks.append(block)
        counter += 1
    stream = b"".join(blocks)
    return stream[:length]


def encrypt_secret(plain_text: str) -> str:
    try:
        pt = plain_text.encode("utf-8")
        nonce = pysecrets.token_bytes(NONCE_SIZE)
        stream = _keystream(APP_KEY, nonce, len(pt))
        ct = bytes(a ^ b for a, b in zip(pt, stream))
        mac = hmac.new(APP_KEY, nonce + ct, hashlib.sha256).digest()
        data = nonce + ct + mac
        return base64.urlsafe_b64encode(data).decode("utf-8")
    except Exception:
        # In case of unexpected error, raise for handler
        raise


def decrypt_secret(encoded: str) -> str:
    try:
        data = base64.urlsafe_b64decode(encoded.encode("utf-8"))
        if len(data) < NONCE_SIZE + MAC_SIZE:
            raise ValueError("Invalid encrypted data")
        nonce = data[:NONCE_SIZE]
        mac = data[-MAC_SIZE:]
        ct = data[NONCE_SIZE:-MAC_SIZE]
        expected_mac = hmac.new(APP_KEY, nonce + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("MAC verification failed")
        stream = _keystream(APP_KEY, nonce, len(ct))
        pt = bytes(a ^ b for a, b in zip(ct, stream))
        return pt.decode("utf-8")
    except Exception:
        # Raise error to be handled by global handler
        raise


# JWT helpers
def create_access_token(user_row: sqlite3.Row) -> str:
    now = int(time.time())
    payload = {
        "sub": int(user_row["id"]),
        "username": user_row["username"],
        "email": user_row["email"],
        "iat": now,
        "exp": now + JWT_EXP_SECONDS,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALG)
    return token


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALG])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )


# Auth dependency
def get_current_user(request: Request, db: sqlite3.Connection = Depends(get_db)) -> sqlite3.Row:
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    token = auth.split(" ", 1)[1].strip()
    payload = decode_access_token(token)
    user_id = payload.get("sub")
    username = payload.get("username")
    email = payload.get("email")
    if user_id is None or username is None or email is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    try:
        cur = db.execute(
            "SELECT id, email, username, password_hash, created_at FROM users WHERE id = ?",
            (user_id,),
        )
        row = cur.fetchone()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    if row is None or row["username"] != username or row["email"] != email:
        # Token does not match current user record (CWE-863)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    return row


# Routes
@app.post(
    "/register",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=True,
)
def register(payload: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    # Validate uniqueness
    try:
        cur = db.execute("SELECT 1 FROM users WHERE email = ? OR username = ?", (payload.email, payload.username))
        exists = cur.fetchone()
        if exists:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use or invalid data",
            )

        # Hash password securely (CWE-522)
        pwd_hash = pbkdf2_sha256.hash(payload.password)
        created_at = datetime.datetime.utcnow().isoformat()

        db.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (payload.email, payload.username, pwd_hash, created_at),
        )
        return {"message": "Registration successful"}
    except HTTPException:
        # Propagate specific error
        raise
    except sqlite3.IntegrityError:
        # Uniqueness constraint violation
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )
    except Exception:
        # Unexpected error
        raise


@app.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=True,
)
def login(payload: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    try:
        cur = db.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (payload.email,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )
        # Verify password
        if not pbkdf2_sha256.verify(payload.password, row["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )

        token = create_access_token(row)
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        raise


@app.post(
    "/set_secret",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=True,
)
def set_secret(
    payload: SetSecretRequest,
    current_user: sqlite3.Row = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    # Authorization check: ensure the token owner matches the requested username (CWE-863)
    if payload.username != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    if len(payload.secret) > MAX_SECRET_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",  # Keep generic message as per limited 400 spec
        )

    try:
        encrypted = encrypt_secret(payload.secret)
        updated_at = datetime.datetime.utcnow().isoformat()

        # Upsert secret for this user (CWE-89: parameterized)
        db.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=excluded.updated_at
            """,
            (int(current_user["id"]), encrypted, updated_at),
        )
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception:
        raise


@app.get(
    "/get_secret",
    response_model=SecretResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=True,
)
def get_secret(
    username: str = Query(..., min_length=1),
    current_user: sqlite3.Row = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    # Authorization check: ensure only the user can access their secret (CWE-284/CWE-863)
    if username != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    try:
        cur = db.execute("SELECT secret FROM secrets WHERE user_id = ?", (int(current_user["id"]),))
        row = cur.fetchone()
        if not row:
            # No secret set yet
            return {"secret": ""}
        encrypted = row["secret"]
        try:
            secret_text = decrypt_secret(encrypted)
        except Exception:
            # If decryption fails, treat as server error (CWE-703)
            raise
        return {"secret": secret_text}
    except HTTPException:
        raise
    except Exception:
        raise


if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000 as required
    uvicorn.run(app, host="0.0.0.0", port=5000)