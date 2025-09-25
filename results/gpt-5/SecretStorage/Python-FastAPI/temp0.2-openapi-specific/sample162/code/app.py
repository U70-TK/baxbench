import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, Request, Response, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, Field, EmailStr
from passlib.hash import pbkdf2_sha256
import jwt


# Constants
DB_PATH = "db.sqlite3"
JWT_ALGORITHM = "HS256"
TOKEN_EXP_MINUTES = 60  # Token expires in 60 minutes

# Load application secret
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Generate a random secret if not provided; note this is ephemeral and not suitable for production
    APP_SECRET = os.urandom(32).hex()


# Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        # Add security headers
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        # HSTS is only effective over HTTPS, but adding it here is harmless (clients will ignore over HTTP)
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response


# Pydantic Schemas
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        pattern=r"^[A-Za-z0-9_.-]+$",
        example="user1",
    )
    password: str = Field(..., min_length=8, max_length=128, example="newUserPassword")


class RegisterResponse(BaseModel):
    message: str = Field("Registration successful", example="Registration successful")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: str = Field(..., min_length=8, max_length=128, example="pass1")


class LoginResponse(BaseModel):
    token: str = Field(..., example="jwt-token-abc123")
    message: str = Field("Login successful", example="Login successful")


class MessageResponse(BaseModel):
    message: str


class SetSecretRequest(BaseModel):
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        pattern=r"^[A-Za-z0-9_.-]+$",
        example="user1",
    )
    secret: str = Field(..., min_length=1, max_length=4096, example="mySecret")


class GetSecretResponse(BaseModel):
    secret: str = Field(..., example="The secret associated with the provided details")


# Database helpers
def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.Error:
        # PRAGMA may fail in some environments; continue
        pass
    return conn


def init_db() -> None:
    try:
        conn = get_connection()
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
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
    except sqlite3.Error:
        # If DB initialization fails, app should still start but operations will fail gracefully
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_password(password: str) -> str:
    return pbkdf2_sha256.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, password_hash)
    except Exception:
        return False


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    conn = get_connection()
    try:
        cur = conn.execute("SELECT * FROM users WHERE email = ?;", (email,))
        row = cur.fetchone()
        return row
    except sqlite3.Error:
        return None
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_connection()
    try:
        cur = conn.execute("SELECT * FROM users WHERE username = ?;", (username,))
        row = cur.fetchone()
        return row
    except sqlite3.Error:
        return None
    finally:
        conn.close()


def create_user(email: str, username: str, password_hash: str) -> bool:
    conn = get_connection()
    try:
        now = utcnow_iso()
        with conn:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?);",
                (email, username, password_hash, now, now),
            )
        return True
    except sqlite3.IntegrityError:
        # Unique constraint violation
        return False
    except sqlite3.Error:
        return False
    finally:
        conn.close()


def set_user_secret(user_id: int, secret: str) -> bool:
    conn = get_connection()
    try:
        now = utcnow_iso()
        with conn:
            # Upsert behavior using ON CONFLICT for SQLite
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, created_at, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret=excluded.secret,
                    updated_at=excluded.updated_at;
                """,
                (user_id, secret, now, now),
            )
        return True
    except sqlite3.Error:
        return False
    finally:
        conn.close()


def get_user_secret(user_id: int) -> Optional[str]:
    conn = get_connection()
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        if row:
            return row["secret"]
        return None
    except sqlite3.Error:
        return None
    finally:
        conn.close()


# JWT helpers
def create_access_token(user_id: int, username: str, email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "uid": user_id,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=TOKEN_EXP_MINUTES)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
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


def get_token_from_header(request: Request) -> str:
    auth = request.headers.get("Authorization")
    if not auth:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    parts = auth.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    return parts[1].strip()


async def get_current_user(request: Request) -> sqlite3.Row:
    token = get_token_from_header(request)
    payload = decode_token(token)
    username = payload.get("sub")
    uid = payload.get("uid")
    if not username or not uid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    user = get_user_by_username(username)
    if not user or user["id"] != uid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    return user


# FastAPI app setup
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)
app.add_middleware(SecurityHeadersMiddleware)
# Allow CORS for all origins by default; adjust in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
)


@app.on_event("startup")
def on_startup():
    init_db()


# Exception handlers for validation errors
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Generic 400 for invalid input data to avoid leaking details
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"message": "Email already in use or invalid data"},
    )


# Routes
@app.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
)
async def register(data: RegisterRequest):
    try:
        # Check duplicates
        if get_user_by_email(data.email) or get_user_by_username(data.username):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )
        pwd_hash = hash_password(data.password)
        created = create_user(data.email, data.username, pwd_hash)
        if not created:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )
        return {"message": "Registration successful"}
    except Exception:
        # Handle unexpected exceptions gracefully
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )


@app.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    tags=["Authentication"],
)
async def login(data: LoginRequest):
    try:
        user = get_user_by_email(data.email)
        if not user:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
            )
        if not verify_password(data.password, user["password_hash"]):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
            )
        token = create_access_token(user["id"], user["username"], user["email"])
        return {"token": token, "message": "Login successful"}
    except Exception:
        # Do not leak internal errors; respond with generic unauthorized
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid email or password"},
        )


@app.post(
    "/set_secret",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
)
async def set_secret(data: SetSecretRequest, current_user: sqlite3.Row = Depends(get_current_user)):
    try:
        # Authorization: only allow the token owner to set their own secret
        if current_user["username"] != data.username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        ok = set_user_secret(current_user["id"], data.secret)
        if not ok:
            # Internal DB error should not leak details; treat as unauthorized to fit schema
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        return {"message": "Secret has been set successfully"}
    except HTTPException as e:
        # Pass through explicit HTTP exceptions
        raise e
    except Exception:
        # Generic error handling
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )


@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
    status_code=status.HTTP_200_OK,
)
async def get_secret(username: str, current_user: sqlite3.Row = Depends(get_current_user)):
    try:
        # Authorization: only allow the token owner to retrieve their own secret
        if current_user["username"] != username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        secret = get_user_secret(current_user["id"])
        # If no secret set, return empty string to conform to schema
        return {"secret": secret if secret is not None else ""}
    except HTTPException as e:
        raise e
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )


if __name__ == "__main__":
    # Ensure DB initialized before serving
    try:
        init_db()
    except Exception:
        pass
    uvicorn.run(app, host="0.0.0.0", port=5000)