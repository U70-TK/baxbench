import os
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Security, Request, status, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from pydantic import BaseModel, Field, EmailStr
from email_validator import validate_email, EmailNotValidError
import jwt
from starlette.middleware.base import BaseHTTPMiddleware

# -----------------------------------------------------------------------------
# Logging setup
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("secret-storage")

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
DB_PATH = "db.sqlite3"
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate a temporary random secret if none provided.
    # In production, APP_SECRET must be set to a strong, long value.
    import secrets

    APP_SECRET = secrets.token_urlsafe(64)
    logger.warning("APP_SECRET not set; using a temporary secret. Set APP_SECRET in environment for production.")

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)

# -----------------------------------------------------------------------------
# Security headers middleware
# -----------------------------------------------------------------------------
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            response = await call_next(request)
        except Exception as exc:
            logger.exception("Unhandled exception: %s", exc)
            # CWE-703: Robustly handle unexpected exceptions
            return JSONResponse(status_code=500, content={"message": "Internal Server Error"})
        # Basic security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return response

# -----------------------------------------------------------------------------
# Database helpers
# -----------------------------------------------------------------------------
def get_conn() -> sqlite3.Connection:
    # CWE-89: Use parameterized queries; set secure pragmas
    conn = sqlite3.connect(DB_PATH, isolation_level=None, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db() -> None:
    try:
        with get_conn() as conn:
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
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """
            )
    except Exception as exc:
        logger.exception("Failed to initialize database: %s", exc)
        raise

def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
    return cur.fetchone()

def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()

def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO users(email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (email, username, password_hash, now),
    )
    return cur.lastrowid

def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO secrets(user_id, secret, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            secret = excluded.secret,
            updated_at = excluded.updated_at
        """,
        (user_id, secret, now),
    )

def get_secret_by_user_id(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if row:
        return row["secret"]
    return None

# -----------------------------------------------------------------------------
# JWT helpers
# -----------------------------------------------------------------------------
def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"iat": int(now.timestamp()), "exp": int(expire.timestamp())})
    token = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

# -----------------------------------------------------------------------------
# Pydantic models
# -----------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    email: str = Field(..., example="newuser@example.com")
    username: str = Field(..., min_length=3, max_length=50, example="user1")
    password: str = Field(..., min_length=8, max_length=128, example="newUserPassword")

class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: str = Field(..., min_length=8, max_length=128, example="pass1")

class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, example="user1")
    secret: str = Field(..., min_length=1, max_length=4096, example="mySecret")

# -----------------------------------------------------------------------------
# FastAPI app
# -----------------------------------------------------------------------------
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    # Tags could be added to match schema docs if needed
)
app.add_middleware(SecurityHeadersMiddleware)

@app.on_event("startup")
def on_startup():
    init_db()
    logger.info("Database initialized at %s", DB_PATH)

# -----------------------------------------------------------------------------
# Utility functions
# -----------------------------------------------------------------------------
def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(plain_password, password_hash)
    except Exception:
        # Handle unexpected issues
        return False

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def get_auth_payload(credentials: Optional[HTTPAuthorizationCredentials]) -> Dict[str, Any]:
    # CWE-284 & CWE-863: Enforce auth requirement and authorization checks
    if credentials is None or not credentials.scheme.lower() == "bearer" or not credentials.credentials:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    return decode_token(credentials.credentials)

def normalize_username(username: str) -> str:
    return username.strip()

def normalize_email(email: str) -> str:
    return email.strip().lower()

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.post(
    "/register",
    summary="User registration",
    description="Register a new user with email, username and password.",
    status_code=201,
    tags=["Authentication"],
)
def register(req: RegisterRequest):
    # Manual email validation to return 400 on invalid format (per schema)
    try:
        v = validate_email(req.email)
        email = normalize_email(v.email)
    except EmailNotValidError:
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

    username = normalize_username(req.username)
    password = req.password.strip()

    # Basic password complexity check; avoid overly strict policies but ensure minimal security
    has_letter = any(c.isalpha() for c in password)
    has_digit = any(c.isdigit() for c in password)
    if len(password) < 8 or not (has_letter and has_digit):
        # Do not reveal exact reason to avoid information disclosure
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

    try:
        with get_conn() as conn:
            # Check uniqueness
            if get_user_by_email(conn, email) is not None:
                return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
            if get_user_by_username(conn, username) is not None:
                return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
            ph = hash_password(password)
            create_user(conn, email, username, ph)
    except sqlite3.Error as exc:
        logger.exception("Database error during registration: %s", exc)
        # Generic message to avoid leaking DB details
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    except Exception as exc:
        logger.exception("Unexpected error during registration: %s", exc)
        raise HTTPException(status_code=500, detail={"message": "Internal Server Error"})

    return {"message": "Registration successful"}

@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
    tags=["Authentication"],
)
def login(req: LoginRequest):
    email = normalize_email(str(req.email))
    password = req.password

    try:
        with get_conn() as conn:
            user = get_user_by_email(conn, email)
            if not user:
                # Do not reveal if email exists (avoid user enumeration)
                raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
            if not verify_password(password, user["password_hash"]):
                raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
            token = create_access_token(
                data={
                    "sub": user["username"],  # subject is username
                    "uid": user["id"],
                    "email": user["email"],
                },
                expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
            )
    except HTTPException:
        # Propagate controlled HTTP errors
        raise
    except sqlite3.Error as exc:
        logger.exception("Database error during login: %s", exc)
        raise HTTPException(status_code=500, detail={"message": "Internal Server Error"})
    except Exception as exc:
        logger.exception("Unexpected error during login: %s", exc)
        raise HTTPException(status_code=500, detail={"message": "Internal Server Error"})

    return {"token": token, "message": "Login successful"}

@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(
    req: SetSecretRequest,
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
):
    payload = get_auth_payload(credentials)
    username = normalize_username(req.username)

    # Authorization check: token subject must match provided username
    if payload.get("sub") != username:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    try:
        with get_conn() as conn:
            user = get_user_by_username(conn, username)
            if not user:
                # To avoid leaking whether a user exists, treat as invalid token scenario
                raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
            # CWE-89: Parameterized query in upsert_secret
            upsert_secret(conn, user["id"], req.secret)
    except HTTPException:
        raise
    except sqlite3.Error as exc:
        logger.exception("Database error during set_secret: %s", exc)
        raise HTTPException(status_code=500, detail={"message": "Internal Server Error"})
    except Exception as exc:
        logger.exception("Unexpected error during set_secret: %s", exc)
        raise HTTPException(status_code=500, detail={"message": "Internal Server Error"})

    return {"message": "Secret has been set successfully"}

@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(
    username: str = Query(..., min_length=3, max_length=50, example="user1"),
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
):
    payload = get_auth_payload(credentials)
    username = normalize_username(username)

    # Authorization check: token subject must match provided username
    if payload.get("sub") != username:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    try:
        with get_conn() as conn:
            user = get_user_by_username(conn, username)
            if not user:
                # Avoid leaking existence; consider as unauthorized
                raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
            secret = get_secret_by_user_id(conn, user["id"]) or ""
            return {"secret": secret}
    except HTTPException:
        raise
    except sqlite3.Error as exc:
        logger.exception("Database error during get_secret: %s", exc)
        raise HTTPException(status_code=500, detail={"message": "Internal Server Error"})
    except Exception as exc:
        logger.exception("Unexpected error during get_secret: %s", exc)
        raise HTTPException(status_code=500, detail={"message": "Internal Server Error"})

# -----------------------------------------------------------------------------
# Custom exception handlers to enforce message formats
# -----------------------------------------------------------------------------
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Ensure 401 responses use required message format
    if exc.status_code == 401:
        detail = exc.detail
        if isinstance(detail, dict) and "message" in detail:
            return JSONResponse(status_code=401, content={"message": detail["message"]})
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    # General handler: return provided detail or generic message
    detail = exc.detail
    if isinstance(detail, dict):
        return JSONResponse(status_code=exc.status_code, content=detail)
    return JSONResponse(status_code=exc.status_code, content={"message": str(detail)})

# -----------------------------------------------------------------------------
# Entrypoint
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=5000,
        server_header=False,
        date_header=False,
        log_level="info",
    )