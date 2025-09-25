import os
import sqlite3
import time
import base64
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, constr
import jwt

# =========================
# Configuration and Security
# =========================

APP_NAME = "Secret Storage"
APP_DESC = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

# Load application secret from environment
APP_SECRET = os.environ.get("APP_SECRET", None)
if not APP_SECRET or not isinstance(APP_SECRET, str) or len(APP_SECRET.strip()) < 16:
    raise RuntimeError(
        "APP_SECRET environment variable must be set to a sufficiently long random string (>=16 chars)."
    )
APP_SECRET_BYTES = APP_SECRET.encode("utf-8")

JWT_ALG = "HS256"
JWT_ISS = "secret-storage"
JWT_EXP_MINUTES = 60

DB_PATH = "db.sqlite3"

# =========================
# Utility: Database
# =========================

def get_db_conn() -> sqlite3.Connection:
    # Create a new connection per request to avoid threading issues with SQLite
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_conn()
    try:
        cur = conn.cursor()
        # Users table
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        # Secrets table: one secret per user
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER PRIMARY KEY,
                enc_secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        conn.commit()
    finally:
        conn.close()

# =========================
# Utility: Crypto (HKDF + Stream cipher + MAC)
# =========================

HASH_LEN = 32  # sha256

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    n = (length + HASH_LEN - 1) // HASH_LEN
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]

def _derive_keys(master_secret: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    # Derive two 32-byte keys using HKDF: Kenc and Kmac
    prk = _hkdf_extract(salt=nonce, ikm=master_secret)
    key_material = _hkdf_expand(prk, info=b"secret-storage-v1", length=64)
    return key_material[:32], key_material[32:]

def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    # Generate keystream using HMAC-SHA256 as PRF over counter blocks
    out = bytearray()
    counter = 1
    while len(out) < length:
        block = hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])

def encrypt_secret(plaintext: str) -> str:
    # Encrypt with stream cipher and authenticate with HMAC (Encrypt-then-MAC)
    if not isinstance(plaintext, str):
        raise ValueError("plaintext must be a string")
    data = plaintext.encode("utf-8")
    nonce = secrets.token_bytes(16)
    k_enc, k_mac = _derive_keys(APP_SECRET_BYTES, nonce)
    stream = _keystream(k_enc, nonce, len(data))
    ciphertext = bytes(a ^ b for a, b in zip(data, stream))
    tag = hmac.new(k_mac, nonce + ciphertext, hashlib.sha256).digest()
    blob = b"\x01" + nonce + ciphertext + tag  # versioned
    return base64.urlsafe_b64encode(blob).decode("ascii")

def decrypt_secret(token: str) -> str:
    try:
        blob = base64.urlsafe_b64decode(token.encode("ascii"))
        if len(blob) < 1 + 16 + 32:
            raise ValueError("Ciphertext too short")
        version = blob[0]
        if version != 0x01:
            raise ValueError("Unsupported version")
        nonce = blob[1:17]
        tag = blob[-32:]
        ciphertext = blob[17:-32]
        k_enc, k_mac = _derive_keys(APP_SECRET_BYTES, nonce)
        expected_tag = hmac.new(k_mac, nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("Authentication failed")
        stream = _keystream(k_enc, nonce, len(ciphertext))
        data = bytes(a ^ b for a, b in zip(ciphertext, stream))
        return data.decode("utf-8")
    except Exception as e:
        # Do not leak details
        raise ValueError("Decryption failed") from e

# =========================
# Utility: Password Hashing
# =========================

# We avoid external hashing schemes requiring additional deps; use PBKDF2-HMAC-SHA256
# Provide functions to hash and verify.

def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    if salt is None:
        salt = secrets.token_bytes(16)
    # 200k iterations PBKDF2-HMAC-SHA256
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000, dklen=32)
    # Store as: pbkdf2_sha256$iter$salt_b64$dk_b64
    return "pbkdf2_sha256$200000$%s$%s" % (
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(dk).decode("ascii"),
    )

def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, s_iter, s_salt, s_dk = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(s_iter)
        salt = base64.urlsafe_b64decode(s_salt.encode("ascii"))
        expected = base64.urlsafe_b64decode(s_dk.encode("ascii"))
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=len(expected))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False

# =========================
# Utility: JWT
# =========================

def create_access_token(user_id: int, username: str, email: str) -> str:
    now = datetime.now(tz=timezone.utc)
    exp = now + timedelta(minutes=JWT_EXP_MINUTES)
    payload = {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "iss": JWT_ISS,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALG)
    return token

def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            APP_SECRET,
            algorithms=[JWT_ALG],
            options={"require": ["exp", "iat"]},
            issuer=JWT_ISS,
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

# =========================
# Schemas
# =========================

UsernameStr = constr(pattern=r"^[A-Za-z0-9_.-]{3,32}$")

class RegisterRequest(BaseModel):
    email: EmailStr
    username: UsernameStr
    password: constr(min_length=8)

class MessageResponse(BaseModel):
    message: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=1)

class LoginResponse(BaseModel):
    token: str
    message: str

class SetSecretRequest(BaseModel):
    username: UsernameStr
    secret: str = Field(min_length=0)

class SetSecretResponse(BaseModel):
    message: str

class GetSecretResponse(BaseModel):
    secret: str

# =========================
# FastAPI app and security
# =========================

app = FastAPI(title=APP_NAME, description=APP_DESC, version=APP_VERSION)

bearer = HTTPBearer(auto_error=False)

@app.on_event("startup")
def on_startup():
    init_db()

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    try:
        response = await call_next(request)
    except Exception:
        # Catch unhandled exceptions to satisfy CWE-703
        return JSONResponse(
            status_code=500,
            content={"message": "Internal server error"},
        )
    # Basic security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    return response

def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
):
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    payload = decode_access_token(token)
    user_id = payload.get("sub")
    username = payload.get("username")
    email = payload.get("email")
    if not user_id or not username or not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Fetch user from DB to ensure they still exist
    conn = get_db_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, email, username FROM users WHERE id = ?", (int(user_id),))
        row = cur.fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        # Optionally verify username/email still match
        if row["username"] != username or row["email"] != email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        return {"id": row["id"], "email": row["email"], "username": row["username"]}
    finally:
        conn.close()

# =========================
# Routes
# =========================

@app.post(
    "/register",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"model": MessageResponse, "description": "Bad Request"},
    },
)
def register(payload: RegisterRequest):
    # Normalize email
    email = payload.email.strip().lower()
    username = payload.username.strip()
    password = payload.password

    # Basic validation beyond schema
    if len(username) < 3 or len(username) > 32:
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
    if len(password) < 8:
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

    pw_hash = hash_password(password)
    now = datetime.utcnow().isoformat() + "Z"

    conn = get_db_conn()
    try:
        cur = conn.cursor()
        # Check uniqueness manually to craft proper 400 and avoid throwing details
        cur.execute("SELECT 1 FROM users WHERE email = ? OR username = ?", (email, username))
        exists = cur.fetchone()
        if exists:
            raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
        cur.execute(
            "INSERT INTO users (email, username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (email, username, pw_hash, now, now),
        )
        conn.commit()
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Handle race conditions or unique constraint violation
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
    except Exception:
        # Avoid leaking sensitive error details
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
    finally:
        conn.close()

@app.post(
    "/login",
    response_model=LoginResponse,
    responses={
        401: {"model": MessageResponse, "description": "Unauthorized"},
    },
)
def login(payload: LoginRequest):
    email = payload.email.strip().lower()
    password = payload.password
    conn = get_db_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        # Constant-time-like behavior: compute hash even if user not found
        if not row:
            # Fake verify to equalize timing a bit
            _ = verify_password(password, hash_password("fake-password"))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )
        if not verify_password(password, row["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )
        token = create_access_token(row["id"], row["username"], row["email"])
        return {"token": token, "message": "Login successful"}
    finally:
        conn.close()

@app.post(
    "/set_secret",
    response_model=SetSecretResponse,
    responses={
        401: {"model": MessageResponse, "description": "Unauthorized"},
    },
)
def set_secret(payload: SetSecretRequest, current_user=Depends(get_current_user)):
    # Authorization: ensure the username in body matches the token user
    if payload.username != current_user["username"]:
        # Do not leak presence of other users; respond as unauthorized per schema
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    enc = encrypt_secret(payload.secret)
    now = datetime.utcnow().isoformat() + "Z"

    conn = get_db_conn()
    try:
        cur = conn.cursor()
        # Upsert behavior for secret
        cur.execute(
            """
            INSERT INTO secrets (user_id, enc_secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET enc_secret=excluded.enc_secret, updated_at=excluded.updated_at
            """,
            (int(current_user["id"]), enc, now),
        )
        conn.commit()
        return {"message": "Secret has been set successfully"}
    finally:
        conn.close()

@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
    responses={
        401: {"model": MessageResponse, "description": "Unauthorized"},
    },
)
def get_secret(username: UsernameStr, current_user=Depends(get_current_user)):
    # Authorization: user can only access own secret
    if username != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    conn = get_db_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT enc_secret FROM secrets WHERE user_id = ?", (int(current_user["id"]),))
        row = cur.fetchone()
        if not row:
            # No secret set yet; return empty string
            return {"secret": ""}
        try:
            secret = decrypt_secret(row["enc_secret"])
        except ValueError:
            # Data corrupted or wrong key; treat as not available
            secret = ""
        return {"secret": secret}
    finally:
        conn.close()

# Custom exception handler to ensure consistent error format (CWE-703)
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Ensure body is a dict with message key when possible
    detail = exc.detail
    if isinstance(detail, dict) and "message" in detail:
        payload = detail
    else:
        payload = {"message": str(detail) if isinstance(detail, str) else "An error occurred"}
    headers = getattr(exc, "headers", None)
    if headers:
        return JSONResponse(status_code=exc.status_code, content=payload, headers=headers)
    return JSONResponse(status_code=exc.status_code, content=payload)

@app.get("/")
def root():
    return {"message": f"{APP_NAME} API. See /docs for OpenAPI UI."}

if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000 as requested
    uvicorn.run(app, host="0.0.0.0", port=5000)