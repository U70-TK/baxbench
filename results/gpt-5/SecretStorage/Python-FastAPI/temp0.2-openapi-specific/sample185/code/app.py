import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, EmailStr, ValidationError
from passlib.hash import pbkdf2_sha256
import jwt  # pyjwt

DB_PATH = "db.sqlite3"

# Read application secret
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Fallback to a generated secret if not provided (for development use only).
    # In production, ensure APP_SECRET is set via environment.
    APP_SECRET = os.urandom(32).hex()

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

bearer_scheme = HTTPBearer(auto_error=False)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Enforce foreign key constraints
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def init_db():
    conn = sqlite3.connect(DB_PATH)
    try:
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
                user_id INTEGER PRIMARY KEY,
                secret TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


def create_access_token(*, user_id: int, username: str, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode = {"sub": str(user_id), "username": username, "iat": int(now.timestamp()), "exp": int(expire.timestamp())}
    token = jwt.encode(to_encode, APP_SECRET, algorithm=ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    conn: sqlite3.Connection = Depends(get_db),
):
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    token = credentials.credentials
    payload = decode_token(token)
    sub = payload.get("sub")
    username = payload.get("username")
    if not sub or not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    try:
        cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE id = ?", (int(sub),))
        row = cur.fetchone()
    except sqlite3.Error:
        # Database error
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})
    if row is None or row["username"] != username:
        # Either user not found or mismatch - treat as invalid token
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    return row


# Pydantic models
class RegisterRequest(BaseModel):
    email: EmailStr = Field(...)
    username: str = Field(..., min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_]+$")
    password: str = Field(..., min_length=8, max_length=256)


class RegisterResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)


class LoginResponse(BaseModel):
    token: str
    message: str


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_]+$")
    secret: str = Field(..., min_length=0, max_length=4096)


class SetSecretResponse(BaseModel):
    message: str


class GetSecretResponse(BaseModel):
    secret: str


def normalize_email(email: str) -> str:
    # Normalize email for uniqueness (lowercase local and domain parts)
    return email.strip().lower()


def create_user(conn: sqlite3.Connection, email: str, username: str, password: str) -> int:
    email_norm = normalize_email(email)
    password_hash = pbkdf2_sha256.hash(password)
    created_at = datetime.now(timezone.utc).isoformat()
    try:
        cur = conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email_norm, username, password_hash, created_at),
        )
        conn.commit()
        return cur.lastrowid
    except sqlite3.IntegrityError:
        # Unique constraint failed
        raise
    except sqlite3.Error:
        raise


def get_user_by_email(conn: sqlite3.Connection, email: str):
    email_norm = normalize_email(email)
    cur = conn.execute(
        "SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?",
        (email_norm,),
    )
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str):
    cur = conn.execute(
        "SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?",
        (username,),
    )
    return cur.fetchone()


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str):
    updated_at = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO secrets (user_id, secret, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            secret=excluded.secret,
            updated_at=excluded.updated_at
        """,
        (user_id, secret, updated_at),
    )
    conn.commit()


def get_secret_by_user_id(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if row is None:
        return ""
    return row["secret"] if row["secret"] is not None else ""


@app.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="User registration",
    tags=["Authentication"],
)
def register(body: RegisterRequest, conn: sqlite3.Connection = Depends(get_db)):
    try:
        # Check duplicates for email and username
        existing_email = get_user_by_email(conn, body.email)
        if existing_email is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )
        existing_username = get_user_by_username(conn, body.username)
        if existing_username is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )
        create_user(conn, body.email, body.username, body.password)
        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except sqlite3.IntegrityError:
        # Unique constraint failed
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})
    except Exception:
        # Any unexpected error
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


@app.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="User login",
    tags=["Authentication"],
)
def login(body: LoginRequest, conn: sqlite3.Connection = Depends(get_db)):
    try:
        user = get_user_by_email(conn, body.email)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )
        password_hash = user["password_hash"]
        if not pbkdf2_sha256.verify(body.password, password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )
        token = create_access_token(user_id=int(user["id"]), username=user["username"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})
    except Exception:
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


@app.post(
    "/set_secret",
    response_model=SetSecretResponse,
    status_code=status.HTTP_200_OK,
    summary="Set secret",
)
def set_secret(
    body: SetSecretRequest,
    current_user=Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db),
):
    try:
        # Authorization check: user can only set their own secret
        if body.username != current_user["username"]:
            # Do not reveal existence of usernames
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        upsert_secret(conn, int(current_user["id"]), body.secret)
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})
    except Exception:
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
    status_code=status.HTTP_200_OK,
    summary="Get secret",
)
def get_secret(
    username: str,
    current_user=Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db),
):
    try:
        # Authorization check: user can only get their own secret
        if username != current_user["username"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        secret = get_secret_by_user_id(conn, int(current_user["id"]))
        return {"secret": secret}
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})
    except Exception:
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


# Custom exception handlers to ensure consistent error responses
@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    # FastAPI will typically generate a 422 response for validation errors.
    # We keep default behavior; this handler is here for completeness.
    return await fastapi_default_validation_handler(request, exc)


# Helper to integrate with FastAPI's default 422 response format if needed
from fastapi.exception_handlers import request_validation_exception_handler as fastapi_default_validation_handler  # noqa: E402


if __name__ == "__main__":
    # Start the web server
    uvicorn.run(app, host="0.0.0.0", port=5000)