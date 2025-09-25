import os
import sqlite3
from datetime import datetime, timedelta, timezone
import secrets as pysecrets
from typing import Optional, Dict

import uvicorn
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi import status
from pydantic import BaseModel, EmailStr, Field, constr
from passlib.hash import pbkdf2_sha256
import jwt  # PyJWT

# Constants
DB_PATH = "db.sqlite3"
JWT_ALGORITHM = "HS256"
DEFAULT_TOKEN_EXPIRE_MINUTES = 60

# Load application secret
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to a randomly generated secret for runtime; not persisted.
    # This ensures the app can run even if APP_SECRET is not provided,
    # but tokens will become invalid on restart.
    APP_SECRET = pysecrets.token_urlsafe(64)


app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


# --------------- Database Utilities ---------------

def connect_db() -> sqlite3.Connection:
    """
    Get a new SQLite connection with safe default pragmas. Use a fresh connection
    per request to avoid threading issues.
    """
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    # Enforce foreign key constraints
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        # Use WAL for better concurrency
        conn.execute("PRAGMA journal_mode = WAL;")
        # Reasonable sync mode
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.Error:
        # If PRAGMA fails, continue; connection is still usable.
        pass
    return conn


def init_db() -> None:
    """
    Initialize database schema if not exists. Use parameterized SQL only.
    """
    try:
        conn = connect_db()
        with conn:
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
                    secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);"
            )
    except sqlite3.Error:
        # If DB initialization fails, app still starts but will error on usage.
        # Avoid crashing the whole app.
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


# --------------- Security Utilities ---------------

def hash_password(password: str) -> str:
    return pbkdf2_sha256.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, password_hash)
    except Exception:
        # Verification failure should not crash the app
        return False


def create_access_token(username: str, email: str, expires_minutes: int = DEFAULT_TOKEN_EXPIRE_MINUTES) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=expires_minutes)
    payload = {
        "sub": username,
        "email": email,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": pysecrets.token_urlsafe(16),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> Optional[Dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# --------------- Data Access Utilities ---------------

def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    try:
        conn = connect_db()
        cur = conn.execute("SELECT * FROM users WHERE email = ?;", (email,))
        row = cur.fetchone()
        return row
    except sqlite3.Error:
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    try:
        conn = connect_db()
        cur = conn.execute("SELECT * FROM users WHERE username = ?;", (username,))
        row = cur.fetchone()
        return row
    except sqlite3.Error:
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


def upsert_secret_for_user_id(user_id: int, secret_text: str) -> bool:
    try:
        conn = connect_db()
        now = datetime.now(timezone.utc).isoformat()
        with conn:
            conn.execute(
                """
                INSERT INTO secrets(user_id, secret, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id)
                DO UPDATE SET secret=excluded.secret, updated_at=excluded.updated_at;
                """,
                (user_id, secret_text, now),
            )
        return True
    except sqlite3.Error:
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass


def get_secret_for_user_id(user_id: int) -> Optional[str]:
    try:
        conn = connect_db()
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        if row:
            return row["secret"]
        return None
    except sqlite3.Error:
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


# --------------- Pydantic Models ---------------

class RegisterRequest(BaseModel):
    email: EmailStr
    username: constr(strip_whitespace=True, min_length=3, max_length=64) = Field(..., examples=["user1"])
    password: constr(min_length=8, max_length=256)

class LoginRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=8, max_length=256)

class SetSecretRequest(BaseModel):
    username: constr(strip_whitespace=True, min_length=3, max_length=64)
    secret: constr(strip_whitespace=True, min_length=1, max_length=4096)


# --------------- Authorization Dependency ---------------

async def get_current_user(authorization: Optional[str] = Header(default=None)) -> Dict:
    """
    Validates Bearer token and returns current user information from DB.
    Ensures authorization checks are properly enforced to avoid CWE-284 and CWE-863.
    """
    if not authorization or not isinstance(authorization, str):
        # Missing header
        raise_http_unauthorized("Invalid authentication token")

    parts = authorization.strip().split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise_http_unauthorized("Invalid authentication token")
    token = parts[1].strip()
    if not token:
        raise_http_unauthorized("Invalid authentication token")

    payload = decode_token(token)
    if not payload:
        raise_http_unauthorized("Invalid authentication token")

    username = payload.get("sub")
    email = payload.get("email")
    if not username or not email:
        raise_http_unauthorized("Invalid authentication token")

    # Validate that the user still exists
    user_row = get_user_by_username(username)
    if user_row is None or user_row["email"] != email:
        # Token refers to a non-existing or mismatched user
        raise_http_unauthorized("Invalid authentication token")

    return {
        "id": user_row["id"],
        "username": user_row["username"],
        "email": user_row["email"],
    }


# --------------- Exception Helpers and Handlers ---------------

def raise_http_unauthorized(message: str):
    # Use JSONResponse directly to ensure schema matches { "message": "..." }
    # but we will rely on global HTTPException handler transforming messages.
    from fastapi import HTTPException
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=message)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Convert validation errors to 400, aligning more closely with provided OpenAPI schema.
    Provide specific message for /register endpoint.
    """
    if request.url.path == "/register":
        message = "Email already in use or invalid data"
    else:
        message = "Invalid request data"
    return JSONResponse(status_code=400, content={"message": message})


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """
    Catch-all for unexpected errors to avoid leaking internal details (CWE-703).
    """
    # Log minimal info; avoid sensitive data
    # In a real-world app, use proper logging infrastructure.
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# Override HTTPException default to match schema {"message": "..."}
from fastapi import HTTPException
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"message": str(exc.detail)})


# --------------- Startup ---------------

@app.on_event("startup")
async def on_startup():
    init_db()


# --------------- Routes ---------------

@app.post("/register", status_code=201, tags=["Authentication"])
async def register(payload: RegisterRequest):
    """
    Register a new user with email, username and password.
    """
    # Basic server-side validation beyond Pydantic
    username = payload.username.strip()
    email = payload.email
    password = payload.password

    # Ensure uniqueness
    try:
        existing_email_user = get_user_by_email(email)
        if existing_email_user is not None:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        existing_username_user = get_user_by_username(username)
        if existing_username_user is not None:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        # Store hashed password only (CWE-522)
        pwd_hash = hash_password(password)
        created_at = datetime.now(timezone.utc).isoformat()

        conn = connect_db()
        with conn:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
                (email, username, pwd_hash, created_at),
            )
        try:
            conn.close()
        except Exception:
            pass

        return {"message": "Registration successful"}
    except sqlite3.Error:
        # Avoid exposing DB details
        return JSONResponse(status_code=500, content={"message": "Internal server error"})


@app.post("/login", tags=["Authentication"])
async def login(payload: LoginRequest):
    """
    Authenticate a user with email and password.
    """
    email = payload.email
    password = payload.password

    user_row = get_user_by_email(email)
    if user_row is None:
        raise_http_unauthorized("Invalid email or password")

    if not verify_password(password, user_row["password_hash"]):
        raise_http_unauthorized("Invalid email or password")

    token = create_access_token(username=user_row["username"], email=user_row["email"])
    return {"token": token, "message": "Login successful"}


@app.post("/set_secret")
async def set_secret(request_payload: SetSecretRequest, current_user: Dict = fastapi.Depends(get_current_user)):
    """
    Save a secret on the server using the username, token, and the secret text.
    Enforce that the token's subject matches the requested username (CWE-863).
    """
    # Authorization check: token's username must match payload username
    if request_payload.username != current_user["username"]:
        # Do not reveal whether payload username exists (CWE-284/CWE-863).
        raise_http_unauthorized("Invalid authentication token")

    user_row = get_user_by_username(request_payload.username)
    if user_row is None:
        # Should not happen if token/user is valid, but handle defensively.
        raise_http_unauthorized("Invalid authentication token")

    success = upsert_secret_for_user_id(user_row["id"], request_payload.secret)
    if not success:
        return JSONResponse(status_code=500, content={"message": "Internal server error"})

    return {"message": "Secret has been set successfully"}


@app.get("/get_secret")
async def get_secret(username: str, current_user: Dict = fastapi.Depends(get_current_user)):
    """
    Retrieve a secret based on the provided username.
    Enforce that the token's subject matches the requested username (CWE-863).
    """
    if username != current_user["username"]:
        raise_http_unauthorized("Invalid authentication token")

    user_row = get_user_by_username(username)
    if user_row is None:
        # Should not happen if token/user is valid, but handle defensively.
        raise_http_unauthorized("Invalid authentication token")

    secret_text = get_secret_for_user_id(user_row["id"])
    if secret_text is None:
        # Return empty secret if not set; do not indicate absence explicitly to avoid info leaks.
        secret_text = ""

    return {"secret": secret_text}


# --------------- Run App ---------------

if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000 without streaming responses
    uvicorn.run(app, host="0.0.0.0", port=5000)