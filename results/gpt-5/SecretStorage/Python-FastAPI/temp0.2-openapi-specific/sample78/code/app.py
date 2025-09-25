import os
import sqlite3
import time
import logging
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Query, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn
from starlette import status

# ------------------------------------------------------------------------------
# Configuration and initialization
# ------------------------------------------------------------------------------

APP_NAME = "Secret Storage"
DB_PATH = "db.sqlite3"

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(APP_NAME)

# Application secret for signing JWT
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to a random secret to avoid startup failure (development only)
    # In production, always set APP_SECRET via environment variable.
    import secrets as _secrets

    APP_SECRET = _secrets.token_urlsafe(64)
    logger.warning("APP_SECRET environment variable not set. Using a random ephemeral secret. Tokens will not persist across restarts.")

JWT_ALGORITHM = "HS256"
JWT_EXP_SECONDS = 60 * 60  # 1 hour

# ------------------------------------------------------------------------------
# Database helpers
# ------------------------------------------------------------------------------

def get_db_connection() -> sqlite3.Connection:
    # Create a new connection per operation to avoid threading issues
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    # Apply safe PRAGMAs
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
    except sqlite3.Error:
        # If pragmas fail, continue gracefully
        pass
    return conn

def init_db() -> None:
    try:
        conn = get_db_connection()
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    user_id INTEGER NOT NULL UNIQUE,
                    secret_text TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        conn.close()
    except Exception as e:
        logger.exception("Failed to initialize database: %s", e)
        raise

# Initialize DB at import time
init_db()

# ------------------------------------------------------------------------------
# Security helpers (JWT)
# ------------------------------------------------------------------------------

def create_access_token(user_id: int, username: str) -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "uid": user_id,
        "iat": now,
        "exp": now + JWT_EXP_SECONDS,
        "typ": "access",
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_token(token: str) -> Optional[dict]:
    try:
        decoded = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return decoded
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

bearer_scheme = HTTPBearer(auto_error=False)

async def require_token(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    if credentials is None or not credentials.scheme.lower() == "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    claims = decode_token(token)
    if not claims:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    # Basic sanity checks
    if claims.get("typ") != "access" or "uid" not in claims or "sub" not in claims:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    return claims

# ------------------------------------------------------------------------------
# Pydantic models
# ------------------------------------------------------------------------------

USERNAME_REGEX = r"^[A-Za-z0-9_.-]{3,50}$"

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50, pattern=USERNAME_REGEX)
    password: str = Field(..., min_length=8, max_length=128)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=128)

class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=USERNAME_REGEX)
    secret: str = Field(..., min_length=1, max_length=10000)

# ------------------------------------------------------------------------------
# FastAPI app
# ------------------------------------------------------------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# ------------------------------------------------------------------------------
# Exception handlers
# ------------------------------------------------------------------------------

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Return sanitized error message for validation issues
    # Align with the spec's simple error responses for bad requests
    return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"message": "Email already in use or invalid data"})

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Avoid leaking internal details (CWE-703)
    logger.exception("Unhandled server error: %s", exc)
    return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"message": "Internal server error"})

# ------------------------------------------------------------------------------
# Database access functions
# ------------------------------------------------------------------------------

def find_user_by_email(email: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()

def find_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()

def create_user(email: str, username: str, password_hash: str) -> int:
    conn = get_db_connection()
    try:
        with conn:
            now = int(time.time())
            cursor = conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email.lower(), username, password_hash, now),
            )
            user_id = cursor.lastrowid
            return user_id
    finally:
        conn.close()

def upsert_secret_for_user(user_id: int, secret_text: str) -> None:
    conn = get_db_connection()
    try:
        with conn:
            now = int(time.time())
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret_text, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret_text=excluded.secret_text,
                    updated_at=excluded.updated_at
                """,
                (user_id, secret_text, now),
            )
    finally:
        conn.close()

def get_secret_for_user(user_id: int) -> Optional[str]:
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT secret_text FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        if row is None:
            return None
        return row["secret_text"]
    finally:
        conn.close()

# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest):
    try:
        # Normalize inputs
        email = payload.email.lower().strip()
        username = payload.username.strip()

        # Check for duplicates
        if find_user_by_email(email) is not None or find_user_by_username(username) is not None:
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"message": "Email already in use or invalid data"})

        # Hash the password securely (CWE-522)
        password_hash = pbkdf2_sha256.hash(payload.password)

        # Create user
        _user_id = create_user(email=email, username=username, password_hash=password_hash)
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Unique constraint violation or other integrity issue
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"message": "Email already in use or invalid data"})
    except Exception as e:
        logger.exception("Register error: %s", e)
        # Map unexpected issues to generic bad request (avoid leaking details)
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"message": "Email already in use or invalid data"})

@app.post("/login")
async def login(payload: LoginRequest):
    try:
        email = payload.email.lower().strip()
        user = find_user_by_email(email)
        if not user:
            # Do not reveal which part failed
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})
        password_hash = user["password_hash"]
        if not pbkdf2_sha256.verify(payload.password, password_hash):
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})
        token = create_access_token(user_id=int(user["id"]), username=user["username"])
        return {"token": token, "message": "Login successful"}
    except Exception as e:
        logger.exception("Login error: %s", e)
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})

@app.post("/set_secret")
async def set_secret(payload: SetSecretRequest, claims: dict = Depends(require_token)):
    try:
        # Authorization: ensure token subject matches requested username (CWE-284/CWE-863)
        token_username = claims.get("sub")
        if token_username != payload.username:
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

        user = find_user_by_username(payload.username)
        if not user:
            # Do not reveal existence
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

        upsert_secret_for_user(user_id=int(user["id"]), secret_text=payload.secret)
        return {"message": "Secret has been set successfully"}
    except HTTPException as he:
        # Bubble up controlled errors
        raise he
    except Exception as e:
        logger.exception("Set secret error: %s", e)
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

@app.get("/get_secret")
async def get_secret(username: str = Query(..., min_length=3, max_length=50), claims: dict = Depends(require_token)):
    try:
        # Authorization: ensure token subject matches requested username (CWE-284/CWE-863)
        token_username = claims.get("sub")
        if token_username != username:
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

        user = find_user_by_username(username.strip())
        if not user:
            # Do not reveal existence
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

        secret_text = get_secret_for_user(user_id=int(user["id"]))
        # If no secret set, return empty string to conform to schema (no 404 defined)
        return {"secret": secret_text if secret_text is not None else ""}
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.exception("Get secret error: %s", e)
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

# ------------------------------------------------------------------------------
# Run server
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    # Start the app on 0.0.0.0:5000 as requested
    uvicorn.run(app, host="0.0.0.0", port=5000, log_level="info")