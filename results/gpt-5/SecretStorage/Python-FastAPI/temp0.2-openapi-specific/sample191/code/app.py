import os
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Request, status, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, constr
from passlib.hash import pbkdf2_sha256
import jwt  # pyjwt

# ----------------------------
# Configuration and Logging
# ----------------------------
APP_NAME = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"
DB_PATH = "db.sqlite3"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(APP_NAME)

APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to a random secret for runtime; in production, ensure APP_SECRET is set.
    # This is logged as a warning to avoid CWE-703 by informing about a potential misconfiguration.
    APP_SECRET = os.urandom(32).hex()
    logger.warning("APP_SECRET env variable is not set. Generated a temporary secret for this runtime. "
                   "Set APP_SECRET for consistent token validation across restarts.")

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # Token validity

# ----------------------------
# FastAPI App
# ----------------------------
app = FastAPI(
    title=APP_NAME,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)


# ----------------------------
# Database Utilities
# ----------------------------
def get_db_connection() -> sqlite3.Connection:
    # Create a new connection per call to ensure thread-safety with FastAPI workers
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.DatabaseError as e:
        # Log and continue; PRAGMA may not be supported in some environments
        logger.debug(f"SQLite PRAGMA setup issue: {e}")
    return conn


def init_db() -> None:
    conn = get_db_connection()
    try:
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
                user_id INTEGER NOT NULL,
                secret_text TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(user_id)
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_secrets_user_id ON secrets (user_id);")
    except sqlite3.DatabaseError as e:
        logger.error(f"Failed to initialize database: {e}")
        raise
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    try:
        init_db()
    except Exception as e:
        # Fail fast on startup DB init errors to avoid running in broken state
        logger.exception(f"Application startup failed due to DB initialization error: {e}")
        raise


# ----------------------------
# Pydantic Models
# ----------------------------
class RegisterRequest(BaseModel):
    email: EmailStr
    username: constr(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_\-]+$") = Field(
        ...,
        description="Alphanumeric with underscores or hyphens, 3-32 chars",
        examples=["user1"],
    )
    password: constr(min_length=1, max_length=1024) = Field(
        ...,
        description="User password (will be hashed before storing)"
    )


class LoginRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=1, max_length=1024)


class SetSecretRequest(BaseModel):
    username: constr(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_\-]+$")
    secret: str


# ----------------------------
# Helper Functions
# ----------------------------
def hash_password(password: str) -> str:
    return pbkdf2_sha256.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, password_hash)
    except Exception:
        # In case of unexpected hash format issues
        return False


def create_access_token(sub_username: str, email: str, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {
        "sub": sub_username,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    # pyjwt returns str in recent versions
    return token


def decode_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def upsert_secret_for_user(conn: sqlite3.Connection, user_id: int, secret_text: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    # Use parameterized SQL to prevent SQL injection (CWE-89)
    # Try update first; if no row updated, insert
    cur = conn.execute("UPDATE secrets SET secret_text = ?, updated_at = ? WHERE user_id = ?", (secret_text, now, user_id))
    if cur.rowcount == 0:
        conn.execute("INSERT INTO secrets (user_id, secret_text, updated_at) VALUES (?, ?, ?)", (user_id, secret_text, now))


def get_secret_for_user(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret_text FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if row:
        return row["secret_text"]
    return None


def extract_bearer_token_from_header(authorization: Optional[str]) -> str:
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    try:
        scheme, token = authorization.split(" ", 1)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    return token


async def get_current_user(request: Request) -> Dict[str, Any]:
    # Extract and validate bearer token
    auth_header = request.headers.get("Authorization")
    token = extract_bearer_token_from_header(auth_header)
    payload = decode_token(token)
    sub_username = payload.get("sub")
    email = payload.get("email")
    if not sub_username or not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, sub_username)
        if user is None or user["email"] != email:
            # Token subject/email mismatch with DB state
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        return {"id": user["id"], "email": user["email"], "username": user["username"]}
    except sqlite3.DatabaseError:
        # Avoid leaking details; log internally
        logger.exception("Database error during user lookup in authentication")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    finally:
        conn.close()


# ----------------------------
# Exception Handlers (Robust handling - CWE-703)
# ----------------------------
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled exception: {exc}")
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# ----------------------------
# Routes
# ----------------------------
@app.post(
    "/register",
    summary="User registration",
    description="Register a new user with email, username and password.",
    status_code=201,
)
async def register_user(payload: RegisterRequest):
    conn = get_db_connection()
    try:
        # Check if email or username already exists
        existing_email = get_user_by_email(conn, payload.email)
        existing_username = get_user_by_username(conn, payload.username)
        if existing_email is not None or existing_username is not None:
            # Do not expose whether it's email or username to avoid user enumeration
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        password_hash = hash_password(payload.password)
        now = datetime.now(timezone.utc).isoformat()
        # Parameterized insertion to avoid SQL injection (CWE-89)
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (payload.email, payload.username, password_hash, now),
        )
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Unique constraint failed or similar
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    except sqlite3.DatabaseError:
        logger.exception("Database error during registration")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password."
)
async def login_user(payload: LoginRequest):
    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, payload.email)
        if user is None:
            # Avoid user enumeration by returning same message for invalid email or password
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        if not verify_password(payload.password, user["password_hash"]):
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        token = create_access_token(sub_username=user["username"], email=user["email"])
        return {"token": token, "message": "Login successful"}
    except sqlite3.DatabaseError:
        logger.exception("Database error during login")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text."
)
async def set_secret(payload: SetSecretRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    # Authorization check: ensure token subject matches the username provided (CWE-863, CWE-284)
    if current_user["username"] != payload.username:
        # Do not leak authorization details, consistent with schema 401
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    conn = get_db_connection()
    try:
        upsert_secret_for_user(conn, current_user["id"], payload.secret)
        return {"message": "Secret has been set successfully"}
    except sqlite3.DatabaseError:
        logger.exception("Database error during setting secret")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username."
)
async def get_secret(username: str = Query(...), current_user: Dict[str, Any] = Depends(get_current_user)):
    # Authorization: user can only access their own secret (CWE-284, CWE-863)
    if current_user["username"] != username:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    conn = get_db_connection()
    try        :
        secret_text = get_secret_for_user(conn, current_user["id"])
        # Schema only documents 200 and 401. If no secret, return empty string.
        return {"secret": secret_text if secret_text is not None else ""}
    except sqlite3.DatabaseError:
        logger.exception("Database error during retrieving secret")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()


# ----------------------------
# Main
# ----------------------------
if __name__ == "__main__":
    # Start the Uvicorn server as requested
    # Bind to 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)