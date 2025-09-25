import os
import sqlite3
import uvicorn
from datetime import datetime, timedelta, timezone
from typing import Optional, Generator

from fastapi import FastAPI, HTTPException, Depends, status, Request, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr, ValidationError
from passlib.hash import pbkdf2_sha256
import jwt

APP_NAME = "Secret Storage"
DB_PATH = "db.sqlite3"

# Security settings
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Load application secret
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to a random secret for development if not supplied.
    # In production, set APP_SECRET to a strong random value.
    import secrets as _secrets

    APP_SECRET = _secrets.token_urlsafe(64)
    print("WARNING: APP_SECRET not set. Using ephemeral secret for this run.")

# FastAPI app
app = FastAPI(
    title=APP_NAME,
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

security = HTTPBearer(auto_error=True)


def get_db() -> Generator[sqlite3.Connection, None, None]:
    """
    Dependency to get a new database connection per request.
    Ensures parameterized queries are used to avoid SQL injection (CWE-89).
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        yield conn
        conn.commit()
    except sqlite3.Error:
        # Rollback on any sqlite error to avoid partial writes
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """
    Initialize the SQLite database with necessary tables.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        with conn:
            conn.execute("PRAGMA foreign_keys = ON;")
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
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            """
            )
    except sqlite3.Error as e:
        # Do not leak internals; raise generic exception for startup failure
        raise RuntimeError("Failed to initialize the database.") from e
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.on_event("startup")
def on_startup():
    init_db()


# Pydantic models
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., description="User email")
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_\-\.]+$")
    password: str = Field(..., min_length=8, max_length=256)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)


class RegisterResponse(BaseModel):
    message: str = "Registration successful"


class LoginResponse(BaseModel):
    token: str
    message: str = "Login successful"


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_\-\.]+$")
    secret: str = Field(..., min_length=1)


class MessageResponse(BaseModel):
    message: str


class SecretResponse(BaseModel):
    secret: str


# Utility functions
def hash_password(password: str) -> str:
    return pbkdf2_sha256.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, password_hash)
    except (ValueError, TypeError):
        return False


def create_access_token(*, user_id: int, username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
        "type": "access",
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            return None
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: sqlite3.Connection = Depends(get_db),
):
    token = credentials.credentials
    payload = decode_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token"
        )
    sub = payload.get("sub")
    username = payload.get("username")
    if not sub or not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token"
        )
    try:
        user_id = int(sub)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token"
        )
    # Fetch the user from DB to ensure it still exists
    try:
        cur = db.execute("SELECT id, email, username, password_hash FROM users WHERE id = ?;", (user_id,))
        row = cur.fetchone()
    except sqlite3.Error:
        # Database error
        raise HTTPException(status_code=500, detail="Internal server error")
    if not row or row["username"] != username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token"
        )
    return {"id": row["id"], "email": row["email"], "username": row["username"]}


# Routes
@app.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=True,
)
def register_user(payload: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    # Validate uniqueness of email and username
    try:
        cur = db.execute(
            "SELECT 1 FROM users WHERE email = ? OR username = ?;",
            (payload.email.lower(), payload.username),
        )
        if cur.fetchone():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use or invalid data",
            )
        # Store password securely (CWE-522)
        pwd_hash = hash_password(payload.password)
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (payload.email.lower(), payload.username, pwd_hash, now),
        )
    except HTTPException:
        raise
    except sqlite3.Error:
        # Handle DB errors without leaking details (CWE-703)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )
    return {"message": "Registration successful"}


@app.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=True,
)
def login(payload: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    try:
        cur = db.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?;",
            (payload.email.lower(),),
        )
        row = cur.fetchone()
        if not row or not verify_password(payload.password, row["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )
        token = create_access_token(user_id=row["id"], username=row["username"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post(
    "/set_secret",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=True,
)
def set_secret(
    payload: SetSecretRequest,
    current_user=Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    # Authorization check (CWE-284 / CWE-863)
    if payload.username != current_user["username"]:
        # Mismatch between token subject and provided username -> treat as unauthorized
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token"
        )

    now = datetime.now(timezone.utc).isoformat()
    try:
        # Upsert secret for the user securely using parameters (CWE-89)
        db.execute(
            """
            INSERT INTO secrets (user_id, secret, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET secret = excluded.secret, updated_at = excluded.updated_at;
            """,
            (current_user["id"], payload.secret, now, now),
        )
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")

    return {"message": "Secret has been set successfully"}


@app.get(
    "/get_secret",
    response_model=SecretResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=True,
)
def get_secret(
    username: str = Query(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_\-\.]+$"),
    current_user=Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    # Authorization check: can only fetch own secret (CWE-284 / CWE-863)
    if username != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token"
        )
    try:
        cur = db.execute("SELECT secret FROM secrets WHERE user_id = ?;", (current_user["id"],))
        row = cur.fetchone()
        secret_value = row["secret"] if row else ""
        return {"secret": secret_value}
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")


# Global exception handlers to avoid leaking internals (CWE-703)
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Ensure consistent JSON error format
    return fastapi_json_response(status_code=exc.status_code, detail=exc.detail)


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Catch-all to prevent unhandled exceptions from leaking details
    return fastapi_json_response(status_code=500, detail="Internal server error")


def fastapi_json_response(status_code: int, detail: str):
    from fastapi.responses import JSONResponse

    # Normalize detail payload to 'message' as per schema examples
    if status_code >= 400:
        return JSONResponse(status_code=status_code, content={"message": detail})
    else:
        return JSONResponse(status_code=status_code, content={"message": detail})


if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000 as requested
    uvicorn.run(app, host="0.0.0.0", port=5000)