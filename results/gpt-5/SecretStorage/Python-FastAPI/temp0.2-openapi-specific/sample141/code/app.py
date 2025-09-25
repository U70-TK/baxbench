import os
import re
import sqlite3
import secrets
import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, status, Request, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from email_validator import validate_email, EmailNotValidError
from passlib.hash import pbkdf2_sha256
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
import uvicorn


# Application metadata (aligns with provided OpenAPI schema)
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Security configuration
bearer_scheme = HTTPBearer(auto_error=False)

# Environment and configuration
DB_PATH = "db.sqlite3"
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Secure fallback to ensure the app is runnable even if APP_SECRET is not provided.
    # In production, always set APP_SECRET via environment variables or secret manager.
    APP_SECRET = secrets.token_urlsafe(64)

JWT_ALG = "HS256"
TOKEN_EXP_MINUTES = 60

# ==========================
# Database helper functions
# ==========================

def get_db_connection() -> sqlite3.Connection:
    # Create a new connection per request/operation to avoid cross-thread issues
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    # Enable safe pragmas
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 3000;")  # 3s wait if database is locked
    except sqlite3.Error:
        # pragma failure should not crash request, still return conn
        pass
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
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);"
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_secrets_user_id ON secrets(user_id);"
        )
        conn.commit()
    except sqlite3.Error:
        # If init fails, we raise to fail fast at startup (CWE-703: anticipate exceptional conditions)
        raise
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# ==========================
# Utility and validation
# ==========================

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,32}$")

def normalize_and_validate_email(email: str) -> str:
    try:
        v = validate_email(email, allow_smtputf8=False)
        return v.normalized
    except EmailNotValidError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        ) from e

def validate_username(username: str) -> None:
    if not USERNAME_RE.fullmatch(username or ""):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )

def validate_password(password: str) -> None:
    if not isinstance(password, str) or len(password) < 8 or len(password) > 128:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )


def create_jwt_token(user_id: int, username: str) -> str:
    now = datetime.datetime.utcnow()
    payload = {
        "sub": username,
        "uid": user_id,
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(minutes=TOKEN_EXP_MINUTES)).timestamp()),
        "jti": secrets.token_hex(16),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALG)
    return token


def verify_authorization(credentials: Optional[HTTPAuthorizationCredentials], expected_username: str, conn: sqlite3.Connection) -> None:
    if credentials is None or not credentials.scheme.lower() == "bearer" or not credentials.credentials:
        # Missing or invalid auth header
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALG])
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_username = payload.get("sub")
    token_user_id = payload.get("uid")

    # Proper authorization check: match token claims to actual user record (CWE-863)
    if not token_username or not token_user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    # username in request must match token subject
    if token_username != expected_username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Cross-check uid with database
    try:
        row = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (expected_username,),
        ).fetchone()
    except sqlite3.Error:
        # Database error: respond with generic auth failure to avoid info leak and handle exception (CWE-703)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    if row is None or row["id"] != token_user_id:
        # uid mismatch or user not found
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )


# ==========================
# Request Models
# ==========================

class RegisterRequest(BaseModel):
    email: str = Field(..., example="newuser@example.com")
    username: str = Field(..., example="user1")
    password: str = Field(..., example="newUserPassword")


class LoginRequest(BaseModel):
    email: str = Field(..., example="user@example.com")
    password: str = Field(..., example="mySecretPassword")


class SetSecretRequest(BaseModel):
    username: str = Field(..., example="user1")
    secret: str = Field(..., example="mySecret")


# ==========================
# Routes
# ==========================

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(req: RegisterRequest):
    # Validate inputs
    email = normalize_and_validate_email(req.email)
    validate_username(req.username)
    validate_password(req.password)

    password_hash = pbkdf2_sha256.hash(req.password)
    created_at = datetime.datetime.utcnow().isoformat()

    conn = get_db_connection()
    try:
        # Check if email or username already exists (CWE-703: handle exceptional conditions proactively)
        exists = conn.execute(
            "SELECT 1 FROM users WHERE email = ? OR username = ?",
            (email, req.username),
        ).fetchone()
        if exists:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )

        # Insert user using parameterized query (CWE-89 safe)
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, req.username, password_hash, created_at),
        )
        conn.commit()
        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except sqlite3.IntegrityError:
        # Unique constraint violated
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    except Exception:
        # Generic failure
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    finally:
        conn.close()


@app.post("/login")
def login(req: LoginRequest):
    # Normalize email
    try:
        email = normalize_and_validate_email(req.email)
    except HTTPException:
        # For login, invalid email format should still yield unauthorized to avoid user enumeration (CWE-284)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        user_id = row["id"]
        username = row["username"]
        stored_hash = row["password_hash"]

        # Verify password with passlib (CWE-522: secure password handling)
        try:
            ok = pbkdf2_sha256.verify(req.password, stored_hash)
        except Exception:
            ok = False

        if not ok:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = create_jwt_token(user_id, username)
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    finally:
        conn.close()


@app.post("/set_secret")
def set_secret(req: SetSecretRequest, credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    # Validate username format
    validate_username(req.username)

    # Validate secret size to avoid excessive payloads
    if not isinstance(req.secret, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Invalid data"},
        )
    if len(req.secret) > 8192:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Invalid data"},
        )

    conn = get_db_connection()
    try:
        # Verify authorization properly (CWE-284 & CWE-863)
        verify_authorization(credentials, req.username, conn)

        # Get user_id
        row = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (req.username,),
        ).fetchone()
        if not row:
            # If user not found, treat as invalid auth to avoid revealing info
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        user_id = row["id"]
        updated_at = datetime.datetime.utcnow().isoformat()

        # Upsert secret using parameterized queries (CWE-89 safe)
        existing = conn.execute(
            "SELECT id FROM secrets WHERE user_id = ?",
            (user_id,),
        ).fetchone()

        if existing:
            conn.execute(
                "UPDATE secrets SET secret = ?, updated_at = ? WHERE id = ?",
                (req.secret, updated_at, existing["id"]),
            )
        else:
            conn.execute(
                "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
                (user_id, req.secret, updated_at),
            )
        conn.commit()

        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except sqlite3.Error:
        # Database error
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )
    finally:
        conn.close()


@app.get("/get_secret")
def get_secret(username: str, credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    # Validate username format
    validate_username(username)

    conn = get_db_connection()
    try:
        # Verify authorization properly (CWE-284 & CWE-863)
        verify_authorization(credentials, username, conn)

        # Get user_id
        row = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not row:
            # Treat missing user as invalid auth to avoid information disclosure
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        user_id = row["id"]
        srow = conn.execute(
            "SELECT secret FROM secrets WHERE user_id = ?",
            (user_id,),
        ).fetchone()

        secret_value = srow["secret"] if srow else ""
        return {"secret": secret_value}
    except HTTPException:
        raise
    except sqlite3.Error:
        # Database error
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )
    finally:
        conn.close()


# Global exception handler: catch unexpected errors (CWE-703)
@app.exception_handler(Exception)
def unhandled_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "Internal server error"},
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)