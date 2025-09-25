import os
import sqlite3
import datetime
import secrets as py_secrets
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, constr
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn

# ----------------------------
# Configuration and constants
# ----------------------------
APP_SECRET = os.environ.get("APP_SECRET") or py_secrets.token_urlsafe(32)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
DB_PATH = "db.sqlite3"

# ----------------------------
# FastAPI app
# ----------------------------
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

security_scheme = HTTPBearer(auto_error=False)

# ----------------------------
# Database utilities
# ----------------------------
def init_db() -> None:
    """
    Initialize the SQLite database and create required tables.
    Uses parameterized statements and constraints for security and consistency.
    """
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        # Create users table
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
        # Indices
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")

        # Create secrets table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(user_id)
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def get_db():
    """
    Dependency to get a per-request SQLite connection.
    Ensures foreign keys, row factory, and safe closure.
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            # Ensure proper resource cleanup even if close fails
            pass


# Initialize DB at startup
init_db()

# ----------------------------
# Pydantic models
# ----------------------------
class RegisterRequest(BaseModel):
    email: EmailStr
    username: constr(pattern=r"^[A-Za-z0-9_.-]{3,32}$") = Field(..., description="Username with 3-32 allowed characters A-Za-z0-9_.-")
    password: constr(min_length=8, max_length=128)


class RegisterResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=8, max_length=128)


class LoginResponse(BaseModel):
    token: str
    message: str


class ErrorResponse(BaseModel):
    message: str


class SetSecretRequest(BaseModel):
    username: constr(pattern=r"^[A-Za-z0-9_.-]{3,32}$")
    secret: constr(min_length=1, max_length=4096)


class SetSecretResponse(BaseModel):
    message: str


class GetSecretResponse(BaseModel):
    secret: str


# ----------------------------
# Security helpers
# ----------------------------
def create_access_token(user_id: int, username: str) -> str:
    """
    Create a signed JWT access token with expiration.
    """
    now = datetime.datetime.utcnow()
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
        "jti": py_secrets.token_hex(16),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def verify_token_and_get_user(credentials: Optional[HTTPAuthorizationCredentials], conn: sqlite3.Connection) -> sqlite3.Row:
    """
    Verify the bearer token and return the corresponding user row.
    Raises 401 with a generic message for any failure to avoid info leaks.
    """
    if credentials is None or not credentials.scheme == "Bearer" or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    token = credentials.credentials
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = int(payload.get("sub", "0"))
        username = payload.get("username")
        if user_id <= 0 or not username:
            raise ValueError("Invalid token payload")
        # Fetch user securely
        cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        if user is None or user["username"] != username:
            # Token does not match existing user info
            raise ValueError("Invalid token subject")
        return user
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )


# ----------------------------
# Routes
# ----------------------------
@app.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"model": ErrorResponse, "description": "Bad Request"},
    },
)
def register(payload: RegisterRequest, conn: sqlite3.Connection = Depends(get_db)):
    """
    Register a new user with email, username, and password.
    Implements:
    - Secure password hashing (CWE-522)
    - Parameterized queries (CWE-89)
    - Robust exception handling (CWE-703)
    """
    # Basic additional validations
    if payload.username.lower() in ("admin", "root", "system"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    lowered_email = payload.email.lower().strip()
    lowered_username = payload.username.strip()

    # Prevent trivial passwords
    if payload.password.lower() in (lowered_username.lower(), lowered_email.lower()):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )

    password_hash = pbkdf2_sha256.using(rounds=29000).hash(payload.password)
    now_iso = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    try:
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (lowered_email, lowered_username, password_hash, now_iso),
        )
        conn.commit()
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Duplicate email or username
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    except Exception:
        # Unexpected DB error
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )


@app.post(
    "/login",
    response_model=LoginResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Unauthorized"},
    },
)
def login(payload: LoginRequest, conn: sqlite3.Connection = Depends(get_db)):
    """
    Authenticate user by email and password. Returns a JWT token on success.
    Implements:
    - Secure password verification and generic failure messages (CWE-522)
    - Parameterized queries (CWE-89)
    - Robust exception handling (CWE-703)
    """
    lowered_email = payload.email.lower().strip()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (lowered_email,))
        user = cur.fetchone()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )
        if not pbkdf2_sha256.verify(payload.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )
        token = create_access_token(user_id=int(user["id"]), username=user["username"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        # Do not leak internal errors to client
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"},
        )


@app.post(
    "/set_secret",
    response_model=SetSecretResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Unauthorized"},
    },
)
def set_secret(
    payload: SetSecretRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    conn: sqlite3.Connection = Depends(get_db),
):
    """
    Save a secret for the authenticated user.
    Implements:
    - Authorization check ensures the actor is the resource owner (CWE-284, CWE-863)
    - Parameterized queries (CWE-89)
    - Robust exception handling (CWE-703)
    """
    user = verify_token_and_get_user(credentials, conn)
    # Authorization: only allow user to set their own secret
    if user["username"] != payload.username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    # Upsert secret securely
    now_iso = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    try:
        # Check existing secret
        cur = conn.execute("SELECT id FROM secrets WHERE user_id = ?", (user["id"],))
        existing = cur.fetchone()
        if existing:
            conn.execute(
                "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
                (payload.secret, now_iso, user["id"]),
            )
        else:
            conn.execute(
                "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
                (user["id"], payload.secret, now_iso),
            )
        conn.commit()
        return {"message": "Secret has been set successfully"}
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )


@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Unauthorized"},
    },
)
def get_secret(
    username: constr(pattern=r"^[A-Za-z0-9_.-]{3,32}$"),
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    conn: sqlite3.Connection = Depends(get_db),
):
    """
    Retrieve the secret for the authenticated user.
    Implements:
    - Authorization check ensures requesting user owns the resource (CWE-284, CWE-863)
    - Parameterized queries (CWE-89)
    - Robust exception handling (CWE-703)
    """
    user = verify_token_and_get_user(credentials, conn)
    if user["username"] != username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user["id"],))
        row = cur.fetchone()
        secret_val = row["secret"] if row and row["secret"] is not None else ""
        return {"secret": secret_val}
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )


# ----------------------------
# Server entry point
# ----------------------------
if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)