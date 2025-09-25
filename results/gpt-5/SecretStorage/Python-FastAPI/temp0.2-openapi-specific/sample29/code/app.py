import os
import re
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt  # pyjwt
from fastapi import FastAPI, Request, Depends, Security
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import uvicorn
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

# Constants and configuration
APP_NAME = "Secret Storage"
APP_DESC = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

DB_PATH = "db.sqlite3"
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

SECRET_KEY = os.environ.get("APP_SECRET")
if not SECRET_KEY:
    # Generate an ephemeral secret if not provided; for production, APP_SECRET should be set.
    SECRET_KEY = os.urandom(32).hex()

# FastAPI app
app = FastAPI(title=APP_NAME, description=APP_DESC, version=APP_VERSION)

# Security scheme
bearer_scheme = HTTPBearer(auto_error=True)

# Middlewares
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # Prevent caching of sensitive responses
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        # HSTS (has effect over HTTPS)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

# Allow CORS (optional - tighten in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict as needed
    allow_credentials=False,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
app.add_middleware(SecurityHeadersMiddleware)

# Exception handlers to return schema-consistent payloads
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    status_code = exc.status_code
    # Make sure we do not leak internal details; use a generic message if detail is not a string
    detail = exc.detail if isinstance(exc.detail, str) else "An error occurred"
    # Map 404 to a generic message
    if status_code == 404:
        detail = "Resource not found"
    return JSONResponse(status_code=status_code, content={"message": detail})

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Validation errors result in Bad Request
    return JSONResponse(status_code=400, content={"message": "Invalid request data"})

# Database utilities
def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def init_db():
    with get_connection() as conn:
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
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE
            );
            """
        )
        conn.commit()

@app.on_event("startup")
def startup_event():
    init_db()

# Security helpers
def hash_password(password: str) -> str:
    # Use a strong, salted hashing algorithm (pbkdf2_sha256 from passlib is pure-python and secure)
    return pbkdf2_sha256.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, hashed)
    except Exception:
        # In case of malformed hashes or errors, deny authentication
        return False

def create_access_token(sub: str, uid: int, email: str, expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {
        "sub": sub,
        "uid": uid,
        "email": email,
        "iat": int(time.time()),
        "exp": expire,
        "iss": APP_NAME,
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM], options={"require": ["exp", "iat", "sub"]})
        return payload
    except jwt.ExpiredSignatureError:
        raise StarletteHTTPException(status_code=401, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise StarletteHTTPException(status_code=401, detail="Invalid authentication token")

# Pydantic models
USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,32}$")

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=32)
    password: str = Field(..., min_length=8, max_length=128)

    def validate_username(self) -> None:
        if not USERNAME_REGEX.fullmatch(self.username):
            raise RequestValidationError([{"loc": ["username"], "msg": "Invalid username", "type": "value_error"}])

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)

class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    secret: str = Field(..., min_length=1, max_length=10000)

    def validate_username(self) -> None:
        if not USERNAME_REGEX.fullmatch(self.username):
            raise RequestValidationError([{"loc": ["username"], "msg": "Invalid username", "type": "value_error"}])

# Data access functions
def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?", (email,))
    return cur.fetchone()

def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?", (username,))
    return cur.fetchone()

def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (email, username, password_hash, now),
    )
    conn.commit()
    return cur.lastrowid

def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    try:
        conn.execute(
            "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
            (user_id, secret, now),
        )
    except sqlite3.IntegrityError:
        conn.execute(
            "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
            (secret, now, user_id),
        )
    conn.commit()

def get_secret_for_user(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if row is None:
        return None
    return row["secret"]

# Auth dependency
def get_current_payload(credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)) -> dict:
    token = credentials.credentials
    payload = decode_token(token)
    return payload

# Routes
@app.post("/register")
async def register(req: RegisterRequest):
    # Validate username pattern explicitly
    req.validate_username()
    try:
        with get_connection() as conn:
            # Check for existing email or username
            existing_email = get_user_by_email(conn, req.email)
            existing_username = get_user_by_username(conn, req.username)
            if existing_email or existing_username:
                return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
            # Create user
            pwd_hash = hash_password(req.password)
            create_user(conn, req.email, req.username, pwd_hash)
            return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except sqlite3.Error:
        # Database errors are unexpected; avoid leaking details
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    except Exception:
        # Generic error handling to avoid CWE-703 issues
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

@app.post("/login")
async def login(req: LoginRequest):
    try:
        with get_connection() as conn:
            user = get_user_by_email(conn, req.email)
            if not user:
                return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
            if not verify_password(req.password, user["password_hash"]):
                return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
            token = create_access_token(sub=user["username"], uid=user["id"], email=user["email"])
            return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})
    except Exception:
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

@app.post("/set_secret")
async def set_secret(req: SetSecretRequest, payload: dict = Depends(get_current_payload)):
    # Validate username
    req.validate_username()
    try:
        token_username = payload.get("sub")
        if not token_username or token_username != req.username:
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
        with get_connection() as conn:
            user = get_user_by_username(conn, req.username)
            if not user:
                # If token is valid but user doesn't exist, treat as invalid auth
                return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
            upsert_secret(conn, user["id"], req.secret)
            return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})
    except Exception:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

@app.get("/get_secret")
async def get_secret(username: str, payload: dict = Depends(get_current_payload)):
    # Basic username validation
    if not USERNAME_REGEX.fullmatch(username):
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    try:
        token_username = payload.get("sub")
        if not token_username or token_username != username:
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
        with get_connection() as conn:
            user = get_user_by_username(conn, username)
            if not user:
                return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
            secret = get_secret_for_user(conn, user["id"])
            if secret is None:
                # If no secret set, return empty string to conform to schema
                secret = ""
            return JSONResponse(status_code=200, content={"secret": secret})
    except Exception:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

# Entry point
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)