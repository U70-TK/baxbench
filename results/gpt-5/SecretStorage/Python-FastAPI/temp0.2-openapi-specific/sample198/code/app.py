import os
import sqlite3
import base64
import hmac
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Tuple

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, Field, EmailStr
from passlib.context import CryptContext
import jwt


# ---------------------------
# Configuration and Security
# ---------------------------

APP_NAME = "Secret Storage"
APP_DESC = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"
DB_PATH = "db.sqlite3"

# Load application secret from environment
_app_secret_env = os.getenv("APP_SECRET")
if _app_secret_env is None or not _app_secret_env.strip():
    # Fallback: generate an ephemeral secret if none provided.
    # Note: secrets encrypted with this key in a running instance will be unreadable after restart.
    _app_secret_env = base64.b64encode(os.urandom(32)).decode("utf-8")

APP_SECRET_BYTES = _app_secret_env.encode("utf-8")

# Password hashing context (pure python scheme to avoid external non-allowed packages)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


# ---------------------------
# Database Layer
# ---------------------------

class Database:
    def __init__(self, path: str):
        # Use check_same_thread=False to allow usage across threads in FastAPI
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _execute(self, query: str, params: Tuple = ()) -> sqlite3.Cursor:
        try:
            cur = self.conn.cursor()
            cur.execute(query, params)
            return cur
        except sqlite3.Error as e:
            # Log error in production; do not leak details to clients
            raise

    def _init_db(self):
        # Ensure foreign keys
        self._execute("PRAGMA foreign_keys = ON;")
        # Create tables
        self._execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """)
        self._execute("""
        CREATE TABLE IF NOT EXISTS secrets (
            user_id INTEGER PRIMARY KEY,
            secret_blob TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)
        # Indexes for performance
        self._execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        self._execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")

    def create_user(self, email: str, username: str, password_hash: str) -> Optional[int]:
        try:
            now = datetime.utcnow().isoformat()
            cur = self._execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, username, password_hash, now),
            )
            return cur.lastrowid
        except sqlite3.IntegrityError:
            return None

    def get_user_by_email(self, email: str) -> Optional[sqlite3.Row]:
        cur = self._execute("SELECT * FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        return row

    def get_user_by_username(self, username: str) -> Optional[sqlite3.Row]:
        cur = self._execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        return row

    def set_user_secret(self, user_id: int, secret_blob: str) -> bool:
        try:
            now = datetime.utcnow().isoformat()
            # Upsert behavior: if secret exists, update; else insert
            existing = self._execute("SELECT user_id FROM secrets WHERE user_id = ?", (user_id,)).fetchone()
            if existing:
                self._execute(
                    "UPDATE secrets SET secret_blob = ?, updated_at = ? WHERE user_id = ?",
                    (secret_blob, now, user_id),
                )
            else:
                self._execute(
                    "INSERT INTO secrets (user_id, secret_blob, updated_at) VALUES (?, ?, ?)",
                    (user_id, secret_blob, now),
                )
            return True
        except sqlite3.Error:
            return False

    def get_user_secret(self, user_id: int) -> Optional[str]:
        cur = self._execute("SELECT secret_blob FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        if row:
            return row["secret_blob"]
        return None


db = Database(DB_PATH)


# ---------------------------
# Crypto Helpers (Stream cipher via HMAC-DRBG + XOR, with HMAC tag)
# ---------------------------

def _prf_hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = _prf_hmac_sha256(key, nonce + counter.to_bytes(8, "big"))
        out.extend(block)
        counter += 1
    return bytes(out[:length])

def encrypt_secret(plaintext: str, key: bytes) -> str:
    pt = plaintext.encode("utf-8")
    nonce = os.urandom(16)
    ks = _keystream(key, nonce, len(pt))
    ct = bytes(a ^ b for a, b in zip(pt, ks))
    tag = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    return (
        base64.b64encode(nonce).decode("ascii")
        + ":"
        + base64.b64encode(ct).decode("ascii")
        + ":"
        + base64.b64encode(tag).decode("ascii")
    )

def decrypt_secret(blob: str, key: bytes) -> Optional[str]:
    try:
        parts = blob.split(":")
        if len(parts) != 3:
            return None
        nonce = base64.b64decode(parts[0])
        ct = base64.b64decode(parts[1])
        tag = base64.b64decode(parts[2])
        expected_tag = hmac.new(key, nonce + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected_tag):
            return None
        ks = _keystream(key, nonce, len(ct))
        pt = bytes(a ^ b for a, b in zip(ct, ks))
        return pt.decode("utf-8")
    except Exception:
        return None


# ---------------------------
# JWT Helpers
# ---------------------------

JWT_ALG = "HS256"
TOKEN_EXP_MINUTES = 30

def create_token(user_id: int, username: str, email: str) -> str:
    now = datetime.utcnow()
    payload = {
        "sub": username,
        "uid": user_id,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=TOKEN_EXP_MINUTES)).timestamp()),
    }
    token = jwt.encode(payload, _app_secret_env, algorithm=JWT_ALG)
    return token

def verify_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, _app_secret_env, algorithms=[JWT_ALG])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# ---------------------------
# Pydantic Models
# ---------------------------

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., min_length=3, max_length=64, example="user1")
    password: str = Field(..., min_length=8, max_length=128, example="newUserPassword")

class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: str = Field(..., min_length=8, max_length=128, example="pass1")

class SetSecretRequest(BaseModel):
    username: str = Field(..., example="user1")
    secret: str = Field(..., example="mySecret")


# ---------------------------
# FastAPI App
# ---------------------------

app = FastAPI(title=APP_NAME, description=APP_DESC, version=APP_VERSION)


def auth_from_request(request: Request) -> Optional[dict]:
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None
    parts = auth_header.split(" ", 1)
    if len(parts) != 2:
        return None
    scheme, token = parts[0].strip(), parts[1].strip()
    if scheme.lower() != "bearer" or not token:
        return None
    payload = verify_token(token)
    return payload


@app.post("/register")
async def register(data: RegisterRequest):
    email = data.email.strip()
    username = data.username.strip()
    password = data.password

    # Basic validation to avoid weak usernames
    if not username.isascii() or any(c.isspace() for c in username):
        return JSONResponse({"message": "Email already in use or invalid data"}, status_code=400)

    # Hash password using strong KDF
    try:
        password_hash = pwd_context.hash(password)
    except Exception:
        return JSONResponse({"message": "Email already in use or invalid data"}, status_code=400)

    try:
        user_id = db.create_user(email=email, username=username, password_hash=password_hash)
        if user_id is None:
            return JSONResponse({"message": "Email already in use or invalid data"}, status_code=400)
        return JSONResponse({"message": "Registration successful"}, status_code=201)
    except Exception:
        return JSONResponse({"message": "Email already in use or invalid data"}, status_code=400)


@app.post("/login")
async def login(data: LoginRequest):
    email = data.email.strip()
    password = data.password

    try:
        user = db.get_user_by_email(email=email)
    except Exception:
        user = None

    if not user:
        return JSONResponse({"message": "Invalid email or password"}, status_code=401)

    # Verify password
    try:
        if not pwd_context.verify(password, user["password_hash"]):
            return JSONResponse({"message": "Invalid email or password"}, status_code=401)
    except Exception:
        return JSONResponse({"message": "Invalid email or password"}, status_code=401)

    token = create_token(user_id=user["id"], username=user["username"], email=user["email"])
    return JSONResponse({"token": token, "message": "Login successful"}, status_code=200)


@app.post("/set_secret")
async def set_secret(request: Request, data: SetSecretRequest):
    # Authorization check
    payload = auth_from_request(request)
    if not payload:
        return JSONResponse({"message": "Invalid authentication token"}, status_code=401)

    username = data.username.strip()
    secret_text = data.secret

    # Enforce that the token subject matches the username to prevent horizontal privilege escalation
    if payload.get("sub") != username:
        return JSONResponse({"message": "Invalid authentication token"}, status_code=401)

    # Fetch user
    try:
        user = db.get_user_by_username(username=username)
    except Exception:
        user = None

    if not user:
        # Avoid leaking existence; treat as unauthorized
        return JSONResponse({"message": "Invalid authentication token"}, status_code=401)

    # Encrypt secret and store
    try:
        blob = encrypt_secret(secret_text, APP_SECRET_BYTES)
        ok = db.set_user_secret(user_id=user["id"], secret_blob=blob)
        if not ok:
            # Handle unexpected DB failure gracefully
            return JSONResponse({"message": "Invalid authentication token"}, status_code=401)
        return JSONResponse({"message": "Secret has been set successfully"}, status_code=200)
    except Exception:
        # Do not leak error details
        return JSONResponse({"message": "Invalid authentication token"}, status_code=401)


@app.get("/get_secret")
async def get_secret(request: Request, username: str):
    # Authorization check
    payload = auth_from_request(request)
    if not payload:
        return JSONResponse({"message": "Invalid authentication token"}, status_code=401)

    username_q = username.strip()

    # Enforce per-user access: only the owner can read their secret
    if payload.get("sub") != username_q:
        return JSONResponse({"message": "Invalid authentication token"}, status_code=401)

    # Fetch user and secret
    try:
        user = db.get_user_by_username(username=username_q)
    except Exception:
        user = None

    if not user:
        return JSONResponse({"message": "Invalid authentication token"}, status_code=401)

    try:
        blob = db.get_user_secret(user_id=user["id"])
        if not blob:
            # No secret set; return empty secret to conform to schema
            return JSONResponse({"secret": ""}, status_code=200)
        secret_text = decrypt_secret(blob, APP_SECRET_BYTES)
        if secret_text is None:
            # If decryption fails, handle gracefully without leaking details
            return JSONResponse({"secret": ""}, status_code=200)
        return JSONResponse({"secret": secret_text}, status_code=200)
    except Exception:
        return JSONResponse({"secret": ""}, status_code=200)


# ---------------------------
# OpenAPI Customization
# ---------------------------

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=APP_NAME,
        version=APP_VERSION,
        description=APP_DESC,
        routes=app.routes,
    )
    # Add security scheme
    openapi_schema.setdefault("components", {}).setdefault("securitySchemes", {})["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Set global security requirement
    openapi_schema["security"] = [{"bearerAuth": []}]
    # Ensure register and login have security: []
    paths = openapi_schema.get("paths", {})
    if "/register" in paths and "post" in paths["/register"]:
        paths["/register"]["post"]["security"] = []
        paths["/register"]["post"]["summary"] = "User registration"
        paths["/register"]["post"]["description"] = "Register a new user with email, username and password."
    if "/login" in paths and "post" in paths["/login"]:
        paths["/login"]["post"]["security"] = []
        paths["/login"]["post"]["summary"] = "User login"
        paths["/login"]["post"]["description"] = "Authenticate a user with email and password."
    # Add tag
    openapi_schema["tags"] = [{"name": "Authentication", "description": "Operations related to user authentication"}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi


# ---------------------------
# Server Entrypoint
# ---------------------------

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)