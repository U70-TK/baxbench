import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Security, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt

# ========================
# Configuration and Setup
# ========================

APP_TITLE = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

# Load application secret (JWT signing key)
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET or not isinstance(APP_SECRET, str) or len(APP_SECRET) < 16:
    # Fallback to a strong random secret if not provided; warn via stdout.
    # In production, always provide a stable APP_SECRET via environment.
    import secrets

    APP_SECRET = secrets.token_urlsafe(48)

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # Token expires in 60 minutes

# Initialize FastAPI app
app = FastAPI(title=APP_TITLE, description=APP_DESCRIPTION, version=APP_VERSION)

# Security Scheme (for OpenAPI docs and header parsing)
bearer_scheme = HTTPBearer(bearerFormat="JWT", auto_error=False)

# Database (sqlite3)
DB_PATH = "db.sqlite3"
_db_lock = threading.Lock()
_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
_conn.row_factory = sqlite3.Row

def init_db() -> None:
    with _db_lock:
        try:
            _conn.execute("PRAGMA foreign_keys = ON;")
            _conn.execute("PRAGMA journal_mode = WAL;")
            _conn.execute(
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
            _conn.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
            _conn.commit()
        except sqlite3.Error:
            # If DB setup fails, we raise a 500 later on first request
            pass

init_db()

# ========================
# Utility and DB helpers
# ========================

def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def validate_username(username: str) -> bool:
    # Allow alphanumeric, underscore, hyphen, 3-50 chars
    if not isinstance(username, str):
        return False
    username = username.strip()
    return bool(re.fullmatch(r"^[A-Za-z0-9_-]{3,50}$", username))

def db_fetchone(query: str, params: tuple) -> Optional[sqlite3.Row]:
    with _db_lock:
        try:
            cur = _conn.execute(query, params)
            return cur.fetchone()
        except sqlite3.Error:
            raise HTTPException(status_code=500, detail="Internal server error")

def db_execute(query: str, params: tuple, commit: bool = False) -> None:
    with _db_lock:
        try:
            _conn.execute(query, params)
            if commit:
                _conn.commit()
        except sqlite3.IntegrityError as e:
            # Specific constraint violation handling will be done by caller
            raise e
        except sqlite3.Error:
            raise HTTPException(status_code=500, detail="Internal server error")

def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    email = email.strip().lower()
    return db_fetchone("SELECT * FROM users WHERE email = ?", (email,))

def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    username = username.strip().lower()
    return db_fetchone("SELECT * FROM users WHERE username = ?", (username,))

def create_user(email: str, username: str, password_hash: str) -> None:
    email = email.strip().lower()
    username = username.strip().lower()
    try:
        db_execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, now_utc_iso()),
            commit=True,
        )
    except sqlite3.IntegrityError:
        # Unique constraint failed for email or username
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")

def upsert_secret(user_id: int, secret: str) -> None:
    existing = db_fetchone("SELECT id FROM secrets WHERE user_id = ?", (user_id,))
    if existing:
        db_execute(
            "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
            (secret, now_utc_iso(), user_id),
            commit=True,
        )
    else:
        db_execute(
            "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
            (user_id, secret, now_utc_iso()),
            commit=True,
        )

def get_secret_for_user(user_id: int) -> Optional[str]:
    row = db_fetchone("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    if row:
        return row["secret"]
    return None

# ========================
# Auth utilities
# ========================

def create_access_token(subject: str, email: str, expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode: Dict[str, Any] = {
        "sub": subject,
        "email": email,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid.uuid4()),
        "iss": APP_TITLE,
    }
    token = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

def get_current_user(credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)) -> sqlite3.Row:
    if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        # Missing or malformed Authorization header
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    payload = decode_token(credentials.credentials)
    username = payload.get("sub")
    email = payload.get("email")
    if not username or not email:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    user = get_user_by_username(str(username).strip().lower())
    if not user:
        # Token refers to non-existent user
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    # Optionally verify email matches too
    if str(user["email"]).strip().lower() != str(email).strip().lower():
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    return user

# ========================
# Pydantic models
# ========================

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., examples=["user1"])
    password: str = Field(..., min_length=8, examples=["newUserPassword"])

class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user1@example.com"])
    password: str = Field(..., min_length=1, examples=["pass1"])

class SetSecretRequest(BaseModel):
    username: str = Field(..., examples=["user1"])
    secret: str = Field(..., min_length=1, examples=["mySecret"])

# ========================
# Routes
# ========================

@app.post(
    "/register",
    status_code=201,
    tags=["Authentication"],
    description="Register a new user with email, username and password.",
    openapi_extra={"security": []},  # Override security: no auth required
)
def register(req: RegisterRequest):
    # Basic validation and normalization
    email = req.email.strip().lower()
    username = req.username.strip().lower()
    password = req.password

    if not validate_username(username):
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")

    # Check if email or username already exists
    if get_user_by_email(email) is not None or get_user_by_username(username) is not None:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")

    # Hash password
    try:
        password_hash = pbkdf2_sha256.hash(password)
    except Exception:
        # Handle rare hashing errors
        raise HTTPException(status_code=500, detail="Internal server error")

    # Create user
    create_user(email=email, username=username, password_hash=password_hash)

    return {"message": "Registration successful"}

@app.post(
    "/login",
    tags=["Authentication"],
    description="Authenticate a user with email and password.",
    openapi_extra={"security": []},  # Override security: no auth required
)
def login(req: LoginRequest):
    email = req.email.strip().lower()
    password = req.password

    user = get_user_by_email(email)
    if not user:
        # Do not reveal user existence
        raise HTTPException(status_code=401, detail="Invalid email or password")

    stored_hash = user["password_hash"]
    try:
        verified = pbkdf2_sha256.verify(password, stored_hash)
    except Exception:
        # If verification fails or hash is corrupted, treat as invalid
        verified = False

    if not verified:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token(subject=user["username"], email=user["email"], expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"token": token, "message": "Login successful"}

@app.post(
    "/set_secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(req: SetSecretRequest, current_user: sqlite3.Row = Depends(get_current_user)):
    # Authorization: ensure the requested username matches the token's user
    requested_username = req.username.strip().lower()
    if not validate_username(requested_username):
        # Do not reveal specifics; keep consistent message for security
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    token_username = str(current_user["username"]).strip().lower()
    if requested_username != token_username:
        # Prevent cross-user access (authorization check)
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    secret_text = req.secret
    if not isinstance(secret_text, str) or len(secret_text.strip()) == 0 or len(secret_text) > 8192:
        # Arbitrary limit to prevent oversized payloads
        raise HTTPException(status_code=400, detail="Invalid secret data")

    # Upsert secret securely
    upsert_secret(user_id=int(current_user["id"]), secret=secret_text)

    return {"message": "Secret has been set successfully"}

@app.get(
    "/get_secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(username: str = Query(..., examples=["user1"]), current_user: sqlite3.Row = Depends(get_current_user)):
    requested_username = username.strip().lower()
    if not validate_username(requested_username):
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    token_username = str(current_user["username"]).strip().lower()
    if requested_username != token_username:
        # Prevent access to other users' secrets
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    secret_text = get_secret_for_user(user_id=int(current_user["id"]))
    if secret_text is None:
        # Return empty string if no secret set, adhering to 200 response
        secret_text = ""

    return {"secret": secret_text}

# ========================
# Exception Handlers
# ========================

@app.exception_handler(HTTPException)
def http_exception_handler(request, exc: HTTPException):
    # Return sanitized error messages to avoid information leakage
    detail = exc.detail if isinstance(exc.detail, str) else "An error occurred"
    return JSONResponse(status_code=exc.status_code, content={"message": detail})

@app.exception_handler(Exception)
def unhandled_exception_handler(request, exc: Exception):
    # Catch-all for unexpected errors (CWE-703 handling)
    return JSONResponse(status_code=500, content={"message": "Internal server error"})

# ========================
# Entrypoint
# ========================

if __name__ == "__main__":
    # Start the webserver on port 5000, listening on 0.0.0.0
    uvicorn.run(app, host="0.0.0.0", port=5000)