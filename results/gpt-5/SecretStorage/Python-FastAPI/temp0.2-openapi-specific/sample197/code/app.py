import os
import sqlite3
import secrets as py_secrets
import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn


# ====== Configuration ======
DB_PATH = "db.sqlite3"
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Fallback secret for development if APP_SECRET is not provided.
    # In production, always set APP_SECRET via environment.
    APP_SECRET = py_secrets.token_urlsafe(64)
    print("Warning: APP_SECRET environment variable not set. Using a temporary in-memory secret.")

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# ====== FastAPI app ======
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    openapi_tags=[
        {"name": "Authentication", "description": "Operations related to user authentication"}
    ],
)

bearer_scheme = HTTPBearer(auto_error=False)


# ====== Database Utilities ======
def get_db_connection() -> sqlite3.Connection:
    try:
        conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, isolation_level=None)
        conn.row_factory = sqlite3.Row
        # Enforce Foreign Keys
        conn.execute("PRAGMA foreign_keys = ON;")
        # Enforce secure settings
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        return conn
    except Exception:
        # This handles rare exceptional conditions in DB connection (CWE-703)
        raise HTTPException(status_code=500, detail="Internal server error")


def init_db():
    conn = None
    try:
        conn = get_db_connection()
        # Create tables with proper constraints; use parameterized statements for operations (CWE-89).
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        if conn:
            conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# ====== Security Utilities ======
def create_access_token(*, uid: int, username: str, email: str) -> str:
    now = datetime.datetime.utcnow()
    exp = now + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "uid": uid,
        "email": email,
        "iat": now,
        "exp": exp,
    }
    try:
        token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
        return token
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except Exception:
        # Invalid token -> Unauthorized (CWE-284, CWE-863)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
):
    # Ensure a token is provided (CWE-284)
    if credentials is None or not credentials.scheme.lower() == "bearer" or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    payload = decode_access_token(credentials.credentials)
    username = payload.get("sub")
    uid = payload.get("uid")
    email = payload.get("email")
    if not username or not uid or not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    # Load user to confirm existence and prevent stale tokens (CWE-863)
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.execute("SELECT id, email, username FROM users WHERE id = ? AND username = ? AND email = ?", (uid, username, email))
        row = cur.fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
            )
        return {"id": row["id"], "email": row["email"], "username": row["username"]}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        if conn:
            conn.close()


# ====== Pydantic Models ======
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., min_length=3, max_length=64, example="user1")
    password: str = Field(..., min_length=8, max_length=128, example="newUserPassword")


class MessageResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: str = Field(..., min_length=8, max_length=128, example="pass1")


class TokenResponse(BaseModel):
    token: str
    message: str


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, example="user1")
    secret: str = Field(..., min_length=1, max_length=8192, example="mySecret")


class SecretResponse(BaseModel):
    secret: str


# ====== Helper DB Functions ======
def find_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def find_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> int:
    try:
        cur = conn.execute(
            "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
            (email, username, password_hash),
        )
        return cur.lastrowid
    except sqlite3.IntegrityError:
        # Duplicate email or username
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    conn.execute(
        """
        INSERT INTO secrets (user_id, secret, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id) DO UPDATE SET
            secret=excluded.secret,
            updated_at=CURRENT_TIMESTAMP;
        """,
        (user_id, secret),
    )


def get_secret_for_user(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    return row["secret"] if row else None


# ====== Routes ======
@app.post(
    "/register",
    summary="User registration",
    description="Register a new user with email, username and password.",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
)
def register(payload: RegisterRequest):
    conn = None
    try:
        conn = get_db_connection()
        # Validate uniqueness
        existing_email = find_user_by_email(conn, payload.email)
        existing_username = find_user_by_username(conn, payload.username)
        if existing_email or existing_username:
            # Do not reveal which field is duplicated to avoid enumeration
            raise HTTPException(status_code=400, detail="Email already in use or invalid data")

        # Hash password securely (CWE-522)
        try:
            password_hash = pbkdf2_sha256.hash(payload.password)
        except Exception:
            raise HTTPException(status_code=500, detail="Internal server error")

        user_id = create_user(conn, payload.email, payload.username, password_hash)
        if not isinstance(user_id, int) or user_id <= 0:
            raise HTTPException(status_code=500, detail="Internal server error")

        return MessageResponse(message="Registration successful")
    except HTTPException:
        raise
    except Exception:
        # Catch-all for rare unexpected errors (CWE-703)
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        if conn:
            conn.close()


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
    response_model=TokenResponse,
    tags=["Authentication"],
)
def login(payload: LoginRequest):
    conn = None
    try:
        conn = get_db_connection()
        user = find_user_by_email(conn, payload.email)
        if not user:
            # Don't disclose whether email exists
            raise HTTPException(status_code=401, detail="Invalid email or password")

        try:
            if not pbkdf2_sha256.verify(payload.password, user["password_hash"]):
                raise HTTPException(status_code=401, detail="Invalid email or password")
        except HTTPException:
            raise
        except Exception:
            # If verification fails for unexpected reasons
            raise HTTPException(status_code=500, detail="Internal server error")

        token = create_access_token(uid=user["id"], username=user["username"], email=user["email"])
        return TokenResponse(token=token, message="Login successful")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        if conn:
            conn.close()


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
    response_model=MessageResponse,
)
def set_secret(payload: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    conn = None
    try:
        # Authorization check: ensure token subject matches requested username (CWE-863)
        if payload.username != current_user["username"]:
            raise HTTPException(status_code=401, detail="Invalid authentication token")

        conn = get_db_connection()
        upsert_secret(conn, current_user["id"], payload.secret)
        return MessageResponse(message="Secret has been set successfully")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        if conn:
            conn.close()


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
    response_model=SecretResponse,
)
def get_secret(username: str = Query(..., example="user1"), current_user: dict = Depends(get_current_user)):
    conn = None
    try:
        # Authorization check: ensure token subject matches requested username (CWE-863)
        if username != current_user["username"]:
            raise HTTPException(status_code=401, detail="Invalid authentication token")

        conn = get_db_connection()
        secret_value = get_secret_for_user(conn, current_user["id"])
        if secret_value is None:
            # Return empty secret if none exists to avoid leaking info
            secret_value = ""
        return SecretResponse(secret=secret_value)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        if conn:
            conn.close()


# ====== Exception handlers for consistent error messages ======
from fastapi.responses import JSONResponse
from fastapi.requests import Request as FastAPIRequest


@app.exception_handler(HTTPException)
def http_exception_handler(request: FastAPIRequest, exc: HTTPException):
    # Standardize error response to include "message" where applicable
    detail = exc.detail if isinstance(exc.detail, str) else "Internal server error"
    # Map detail to "message" for 4xx responses as per schema examples
    body = {"message": detail} if exc.status_code in (400, 401) else {"detail": detail}
    return JSONResponse(status_code=exc.status_code, content=body)


# ====== Entrypoint ======
if __name__ == "__main__":
    # Start uvicorn server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)