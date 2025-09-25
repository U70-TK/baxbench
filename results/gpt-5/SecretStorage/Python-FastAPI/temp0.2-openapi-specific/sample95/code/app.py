import os
import re
import sqlite3
import time
from typing import Optional, Tuple

from fastapi import FastAPI, Request, status
from fastapi import Body, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import HTTPException
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
import jwt
import uvicorn

# ------------------------------------------------------------------------------
# Configuration and Security
# ------------------------------------------------------------------------------

APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET or not isinstance(APP_SECRET, str) or len(APP_SECRET.strip()) < 16:
    # For security, require a sufficiently long APP_SECRET.
    # This avoids weak tokens or accidental missing secret.
    raise RuntimeError(
        "APP_SECRET environment variable must be set to a strong secret (>=16 characters)."
    )
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRES_SECONDS = 3600  # 1 hour

# Password hashing context using a strong scheme without external dependencies
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# ------------------------------------------------------------------------------
# Database Utilities
# ------------------------------------------------------------------------------

DB_PATH = "db.sqlite3"


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(
        DB_PATH,
        isolation_level=None,  # autocommit behavior; control transactions yourself if needed
        detect_types=sqlite3.PARSE_DECLTYPES,
        check_same_thread=False,  # allow use across threads in FastAPI
    )
    conn.row_factory = sqlite3.Row
    # Strengthen SQLite reliability
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn


def initialize_db() -> None:
    conn = get_db_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            """
        )
    finally:
        conn.close()


# ------------------------------------------------------------------------------
# Models
# ------------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., min_length=3, max_length=50, example="user1")
    password: str = Field(..., min_length=8, max_length=128, example="newUserPassword")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: str = Field(..., min_length=8, max_length=128, example="pass1")


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, example="user1")
    secret: str = Field(..., min_length=1, max_length=4096, example="mySecret")


# ------------------------------------------------------------------------------
# Utility Functions
# ------------------------------------------------------------------------------

USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_.-]{3,50}$")


def validate_username(username: str) -> bool:
    return bool(USERNAME_REGEX.fullmatch(username))


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(plain_password, password_hash)
    except Exception:
        # Exception safety (CWE-703): return False on unexpected verification error
        return False


def create_access_token(username: str, email: str) -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "email": email,
        "iat": now,
        "exp": now + ACCESS_TOKEN_EXPIRES_SECONDS,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    # pyjwt returns str
    return token


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception:
        # Exception safety (CWE-703)
        return None


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (email,),
        )
        return cur.fetchone()
    except sqlite3.Error:
        return None


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE username = ?",
            (username,),
        )
        return cur.fetchone()
    except sqlite3.Error:
        return None


def set_user_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> bool:
    try:
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET
                secret = excluded.secret,
                updated_at = CURRENT_TIMESTAMP
            """,
            (user_id, secret),
        )
        return True
    except sqlite3.Error:
        return False


def get_user_secret(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    try:
        cur = conn.execute(
            "SELECT secret FROM secrets WHERE user_id = ?",
            (user_id,),
        )
        row = cur.fetchone()
        return row["secret"] if row else None
    except sqlite3.Error:
        return None


def parse_authorization_header(request: Request) -> Optional[str]:
    auth = request.headers.get("Authorization")
    if not auth:
        return None
    parts = auth.strip().split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1]


def authorize_request(request: Request) -> Tuple[Optional[dict], Optional[str]]:
    """
    Returns (payload, error_message). If payload is None, error_message explains why.
    """
    token = parse_authorization_header(request)
    if not token:
        return None, "Invalid authentication token"
    payload = decode_token(token)
    if not payload:
        return None, "Invalid authentication token"
    # Basic claims validation
    sub = payload.get("sub")
    email = payload.get("email")
    if not isinstance(sub, str) or not isinstance(email, str):
        return None, "Invalid authentication token"
    return payload, None


# ------------------------------------------------------------------------------
# FastAPI Application
# ------------------------------------------------------------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    openapi_version="3.0.3",
)

# Minimal CORS setup (optional; not required by schema). Keeps origins limited by default.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_credentials=False,
    allow_methods=["POST", "GET"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.on_event("startup")
def startup_event():
    initialize_db()


# Custom exception handler to match schema responses and avoid leaking details.
@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    status_code = exc.status_code
    # Use provided detail string as "message"; fallback to generic
    msg = exc.detail if isinstance(exc.detail, str) else "An error occurred"
    # For known statuses, return the schema's message field.
    if status_code in (400, 401, 403, 404):
        return JSONResponse(status_code=status_code, content={"message": msg})
    # For others, return generic error message
    return JSONResponse(status_code=status_code, content={"message": "An error occurred"})


# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@app.post(
    "/register",
    summary="User registration",
    tags=["Authentication"],
)
async def register(payload: RegisterRequest = Body(...)):
    # Validate username format explicitly
    if not validate_username(payload.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )
    try:
        conn = get_db_connection()
        # Normalize email to lowercase to avoid case-related duplicates
        email = payload.email.lower().strip()
        username = payload.username.strip()
        password_h = hash_password(payload.password)

        # Check for duplicates using parameterized queries (CWE-89 protection)
        cur = conn.execute("SELECT id FROM users WHERE email = ? OR username = ?", (email, username))
        existing = cur.fetchone()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use or invalid data",
            )

        conn.execute(
            "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
            (email, username, password_h),
        )
        # Success
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"message": "Registration successful"},
        )
    except HTTPException:
        # Propagate explicit HTTP exceptions
        raise
    except Exception:
        # Exception safety (CWE-703)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.post(
    "/login",
    summary="User login",
    tags=["Authentication"],
)
async def login(payload: LoginRequest = Body(...)):
    try:
        conn = get_db_connection()
        email = payload.email.lower().strip()
        user = get_user_by_email(conn, email)
        if not user:
            # Do not reveal whether email exists
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )
        # Verify password securely
        if not verify_password(payload.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )
        # Create JWT
        token = create_access_token(username=user["username"], email=user["email"])
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"token": token, "message": "Login successful"},
        )
    except HTTPException:
        raise
    except Exception:
        # Exception safety; avoid leaking internals
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.post(
    "/set_secret",
    summary="Set secret",
    tags=["Authentication"],
)
async def set_secret(request: Request, payload: SetSecretRequest = Body(...)):
    # Authorization: Global bearer required; ensure token provided and valid
    token_payload, err = authorize_request(request)
    if err or not token_payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    # Ensure the acting user matches the provided username (CWE-863 protection)
    token_username = token_payload.get("sub")
    if payload.username.strip() != token_username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    # Validate provided username format
    if not validate_username(payload.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )
    # Validate secret length
    if not isinstance(payload.secret, str) or len(payload.secret) < 1 or len(payload.secret) > 4096:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )

    try:
        conn = get_db_connection()
        user = get_user_by_username(conn, payload.username.strip())
        if not user:
            # If user doesn't exist, treat as unauthorized to avoid info leak
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
            )
        success = set_user_secret(conn, user_id=user["id"], secret=payload.secret)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use or invalid data",
            )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "Secret has been set successfully"},
        )
    except HTTPException:
        raise
    except Exception:
        # Exception safety
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.get(
    "/get_secret",
    summary="Get secret",
    tags=["Authentication"],
)
async def get_secret(request: Request, username: str = Query(..., example="user1")):
    # Authorization: Global bearer required; ensure token provided and valid
    token_payload, err = authorize_request(request)
    if err or not token_payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    # Ensure the acting user matches the requested username (CWE-863 protection)
    token_username = token_payload.get("sub")
    if username.strip() != token_username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    # Validate username format
    if not validate_username(username):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    try:
        conn = get_db_connection()
        user = get_user_by_username(conn, username.strip())
        if not user:
            # If user doesn't exist, treat as unauthorized
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
            )
        secret_val = get_user_secret(conn, user_id=user["id"])
        if secret_val is None:
            # If no secret is set, return an empty string to conform to schema
            secret_val = ""
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"secret": secret_val},
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ------------------------------------------------------------------------------
# Run the server
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    # Run uvicorn server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)