import os
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Depends, Body, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr, ValidationError
from passlib.context import CryptContext
from email_validator import validate_email, EmailNotValidError
import jwt
import uvicorn

# ----------------------------
# Configuration & Security
# ----------------------------

# Load APP_SECRET from environment
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Fallback to a securely generated random secret for runtime if not provided
    APP_SECRET = uuid.uuid4().hex + uuid.uuid4().hex

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)

DB_PATH = "db.sqlite3"
_db_lock = threading.RLock()

# ----------------------------
# Database Utilities
# ----------------------------

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)  # autocommit
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    with _db_lock:
        conn = get_db_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS secrets (
                    user_id INTEGER PRIMARY KEY,
                    secret_text TEXT,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            """)
        finally:
            conn.close()

def create_user(email: str, username: str, password_hash: str) -> bool:
    with _db_lock:
        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
                (email, username, password_hash, datetime.now(timezone.utc).isoformat())
            )
            return True
        except sqlite3.IntegrityError:
            return False
        except Exception:
            # In case of rare DB issues (CWE-703), fail safely
            return False
        finally:
            conn.close()

def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    with _db_lock:
        conn = get_db_connection()
        try:
            cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?;", (email,))
            return cur.fetchone()
        finally:
            conn.close()

def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    with _db_lock:
        conn = get_db_connection()
        try:
            cur = conn.execute("SELECT id, email, username FROM users WHERE username = ?;", (username,))
            return cur.fetchone()
        finally:
            conn.close()

def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    with _db_lock:
        conn = get_db_connection()
        try:
            cur = conn.execute("SELECT id, email, username FROM users WHERE id = ?;", (user_id,))
            return cur.fetchone()
        finally:
            conn.close()

def upsert_secret(user_id: int, secret_text: str) -> bool:
    with _db_lock:
        conn = get_db_connection()
        try:
            # Use parameterized queries to prevent SQL injection (CWE-89)
            conn.execute("""
                INSERT INTO secrets (user_id, secret_text, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret_text = excluded.secret_text,
                    updated_at = excluded.updated_at;
            """, (user_id, secret_text, datetime.now(timezone.utc).isoformat()))
            return True
        except Exception:
            return False
        finally:
            conn.close()

def get_secret_by_user_id(user_id: int) -> Optional[str]:
    with _db_lock:
        conn = get_db_connection()
        try:
            cur = conn.execute("SELECT secret_text FROM secrets WHERE user_id = ?;", (user_id,))
            row = cur.fetchone()
            return row["secret_text"] if row else None
        finally:
            conn.close()

# ----------------------------
# JWT Utilities
# ----------------------------

def create_access_token(*, uid: int, email: str, username: str, expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode = {
        "sub": email,
        "uid": uid,
        "username": username,
        "iat": datetime.now(timezone.utc),
        "exp": expire,
    }
    # PyJWT expects datetimes to be timestamps or datetimes; it'll handle datetimes.
    token = jwt.encode(to_encode, APP_SECRET, algorithm=ALGORITHM)
    return token

def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# ----------------------------
# Pydantic Models
# ----------------------------

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., min_length=3, max_length=50, examples=["user1"])
    password: str = Field(..., min_length=8, max_length=128, examples=["newUserPassword"])

class RegisterResponse(BaseModel):
    message: str = Field(..., examples=["Registration successful"])

class ErrorMessageResponse(BaseModel):
    message: str

class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user@example.com"])
    password: str = Field(..., min_length=8, max_length=128, examples=["mySecretPassword"])

class LoginResponse(BaseModel):
    token: str = Field(..., examples=["jwt-token-abc123"])
    message: str = Field(..., examples=["Login successful"])

class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, examples=["user1"])
    secret: str = Field(..., min_length=1, max_length=4096, examples=["mySecret"])

class SetSecretResponse(BaseModel):
    message: str = Field(..., examples=["Secret has been set successfully"])

class GetSecretResponse(BaseModel):
    secret: str = Field(..., examples=["The secret associated with the provided details"])

# ----------------------------
# FastAPI App
# ----------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    openapi_tags=[{"name": "Authentication", "description": "Operations related to user authentication"}],
)

# Initialize database at startup
init_db()

# ----------------------------
# Helper Functions
# ----------------------------

def validate_username(username: str) -> bool:
    # Allow alphanumeric and underscores and hyphens, 3..50 chars
    if not (3 <= len(username) <= 50):
        return False
    for ch in username:
        if not (ch.isalnum() or ch in ("_", "-")):
            return False
    return True

def validate_password_strength(password: str) -> bool:
    # Basic checks: length, at least one letter and one digit
    if len(password) < 8 or len(password) > 128:
        return False
    has_letter = any(c.isalpha() for c in password)
    has_digit = any(c.isdigit() for c in password)
    return has_letter and has_digit

def unauthorized_response(message: str = "Invalid authentication token"):
    return JSONResponse(status_code=401, content={"message": message})

def bad_request_response(message: str = "Email already in use or invalid data"):
    return JSONResponse(status_code=400, content={"message": message})

# ----------------------------
# Dependencies
# ----------------------------

def get_current_token_credentials(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> Optional[dict]:
    # Ensure Authorization header is present and valid
    if credentials is None or not credentials.scheme.lower() == "bearer" or not credentials.credentials:
        return None
    payload = decode_token(credentials.credentials)
    return payload

# ----------------------------
# Routes
# ----------------------------

@app.post("/register", response_model=RegisterResponse, tags=["Authentication"])
def register(payload: RegisterRequest = Body(...)):
    # Validate inputs
    try:
        # Normalize email
        try:
            validation = validate_email(payload.email)
            email_norm = validation.email
        except EmailNotValidError:
            return bad_request_response("Email already in use or invalid data")

        username = payload.username.strip()
        if not validate_username(username):
            return bad_request_response("Email already in use or invalid data")

        password = payload.password
        if not validate_password_strength(password):
            return bad_request_response("Email already in use or invalid data")

        # Hash password securely to avoid CWE-522
        password_hash = pwd_context.hash(password)

        # Create user
        created = create_user(email_norm, username, password_hash)
        if not created:
            return bad_request_response("Email already in use or invalid data")

        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except Exception:
        # Handle rare unexpected exceptions safely (CWE-703)
        return bad_request_response("Email already in use or invalid data")

@app.post("/login", response_model=LoginResponse, tags=["Authentication"])
def login(payload: LoginRequest = Body(...)):
    try:
        try:
            # Validate email format
            validation = validate_email(payload.email)
            email_norm = validation.email
        except EmailNotValidError:
            return unauthorized_response("Invalid email or password")

        user = get_user_by_email(email_norm)
        if not user:
            return unauthorized_response("Invalid email or password")

        # Verify password
        if not pwd_context.verify(payload.password, user["password_hash"]):
            return unauthorized_response("Invalid email or password")

        token = create_access_token(uid=int(user["id"]), email=user["email"], username=user["username"])
        return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})
    except Exception:
        return unauthorized_response("Invalid email or password")

@app.post("/set_secret", response_model=SetSecretResponse)
def set_secret(payload: SetSecretRequest = Body(...), token_payload: Optional[dict] = Depends(get_current_token_credentials)):
    # Authorization required; enforce checks to mitigate CWE-284 and CWE-863
    if token_payload is None:
        return unauthorized_response("Invalid authentication token")

    try:
        username = payload.username.strip()
        if not validate_username(username):
            return unauthorized_response("Invalid authentication token")

        # Ensure token corresponds to the same user as the provided username
        uid = token_payload.get("uid")
        if uid is None:
            return unauthorized_response("Invalid authentication token")

        db_user = get_user_by_id(int(uid))
        if not db_user or db_user["username"] != username:
            return unauthorized_response("Invalid authentication token")

        # Persist the secret securely using parameterized queries (CWE-89)
        secret_text = payload.secret
        if not (1 <= len(secret_text) <= 4096):
            return unauthorized_response("Invalid authentication token")

        if not upsert_secret(int(uid), secret_text):
            # Handle unexpected DB conditions gracefully (CWE-703)
            return unauthorized_response("Invalid authentication token")

        return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})
    except Exception:
        return unauthorized_response("Invalid authentication token")

@app.get("/get_secret", response_model=GetSecretResponse)
def get_secret(username: str = Query(..., examples=["user1"]), token_payload: Optional[dict] = Depends(get_current_token_credentials)):
    if token_payload is None:
        return unauthorized_response("Invalid authentication token")

    try:
        username_q = username.strip()
        if not validate_username(username_q):
            return unauthorized_response("Invalid authentication token")

        uid = token_payload.get("uid")
        if uid is None:
            return unauthorized_response("Invalid authentication token")

        db_user = get_user_by_id(int(uid))
        if not db_user or db_user["username"] != username_q:
            return unauthorized_response("Invalid authentication token")

        secret_text = get_secret_by_user_id(int(uid))
        # Even if not set, return empty string to conform to schema (avoid leaking info)
        if secret_text is None:
            secret_text = ""

        return JSONResponse(status_code=200, content={"secret": secret_text})
    except Exception:
        return unauthorized_response("Invalid authentication token")

# ----------------------------
# Startup
# ----------------------------

if __name__ == "__main__":
    # Start uvicorn server as required
    uvicorn.run(app, host="0.0.0.0", port=5000)