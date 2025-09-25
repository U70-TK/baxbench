import os
import sqlite3
import datetime
from typing import Optional

from fastapi import FastAPI, Depends, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, constr
import jwt
from passlib.hash import pbkdf2_sha256
import uvicorn


# ==========================
# Configuration and Security
# ==========================

APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET or not isinstance(APP_SECRET, str) or len(APP_SECRET.strip()) < 16:
    # Fail fast if APP_SECRET is not provided or too weak; helps avoid CWE-703, CWE-522.
    raise RuntimeError(
        "APP_SECRET environment variable must be set to a sufficiently long secret string."
    )

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DB_NAME = "db.sqlite3"

# Custom exception to ensure response bodies match the required schema (message property).
class APIError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


# ==========================
# FastAPI App Initialization
# ==========================

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

security = HTTPBearer(auto_error=False)


# ==========================
# Database Utilities
# ==========================

def get_connection() -> sqlite3.Connection:
    # Create a new connection per operation to avoid threading issues (CWE-703).
    conn = sqlite3.connect(DB_NAME, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
    except sqlite3.Error:
        conn.close()
        raise
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
                    created_at DATETIME NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT NOT NULL,
                    updated_at DATETIME NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
    except sqlite3.Error as e:
        # Avoid leaking internal details; log or handle appropriately in real systems.
        raise RuntimeError("Failed to initialize database.") from e
    finally:
        try:
            conn.close()
        except Exception:
            pass


def db_get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    try:
        conn = get_connection()
        cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?;", (email,))
        row = cur.fetchone()
        return row
    except sqlite3.Error:
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


def db_get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    try:
        conn = get_connection()
        cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE id = ?;", (user_id,))
        row = cur.fetchone()
        return row
    except sqlite3.Error:
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


def db_get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    try:
        conn = get_connection()
        cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?;", (username,))
        row = cur.fetchone()
        return row
    except sqlite3.Error:
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


def db_create_user(email: str, username: str, password_hash: str) -> bool:
    try:
        conn = get_connection()
        with conn:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
                (email, username, password_hash, datetime.datetime.utcnow()),
            )
        return True
    except sqlite3.IntegrityError:
        # Duplicate email or username
        return False
    except sqlite3.Error:
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass


def db_set_secret_for_user(user_id: int, secret_text: str) -> bool:
    try:
        conn = get_connection()
        with conn:
            # Upsert-like behavior: try update first, if no rows affected then insert.
            updated = conn.execute(
                "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?;",
                (secret_text, datetime.datetime.utcnow(), user_id),
            ).rowcount
            if updated == 0:
                conn.execute(
                    "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?);",
                    (user_id, secret_text, datetime.datetime.utcnow()),
                )
        return True
    except sqlite3.Error:
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass


def db_get_secret_for_user(user_id: int) -> Optional[str]:
    try:
        conn = get_connection()
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        return row["secret"] if row else None
    except sqlite3.Error:
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ==========================
# Token Utilities
# ==========================

def create_access_token(user_row: sqlite3.Row) -> str:
    now = datetime.datetime.utcnow()
    payload = {
        "sub": user_row["username"],
        "uid": user_row["id"],
        "email": user_row["email"],
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise APIError(status_code=401, message="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise APIError(status_code=401, message="Invalid authentication token")


async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> sqlite3.Row:
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise APIError(status_code=401, message="Invalid authentication token")
    token = credentials.credentials
    if not token or not isinstance(token, str) or token.strip() == "":
        raise APIError(status_code=401, message="Invalid authentication token")
    payload = decode_access_token(token)
    uid = payload.get("uid")
    sub = payload.get("sub")
    if not isinstance(uid, int) or not isinstance(sub, str):
        raise APIError(status_code=401, message="Invalid authentication token")
    user = db_get_user_by_id(uid)
    if user is None or user["username"] != sub:
        # Ensure authorization is correctly checked (CWE-863).
        raise APIError(status_code=401, message="Invalid authentication token")
    return user


# ==========================
# Pydantic Models
# ==========================

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: constr(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_]+$") = Field(..., example="user1")
    password: constr(min_length=8, max_length=128) = Field(..., example="newUserPassword")


class RegisterResponse(BaseModel):
    message: str = Field(..., example="Registration successful")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: constr(min_length=8, max_length=128) = Field(..., example="pass1")


class LoginResponse(BaseModel):
    token: str = Field(..., example="jwt-token-abc123")
    message: str = Field(..., example="Login successful")


class ErrorResponse(BaseModel):
    message: str


class SetSecretRequest(BaseModel):
    username: constr(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_]+$") = Field(..., example="user1")
    secret: constr(min_length=1, max_length=8192) = Field(..., example="mySecret")


class SetSecretResponse(BaseModel):
    message: str = Field(..., example="Secret has been set successfully")


class GetSecretResponse(BaseModel):
    secret: str = Field(..., example="The secret associated with the provided details")


# ==========================
# Exception Handlers
# ==========================

@app.exception_handler(APIError)
async def handle_api_error(request, exc: APIError):
    return JSONResponse(status_code=exc.status_code, content={"message": exc.message})


@app.exception_handler(Exception)
async def handle_unexpected_error(request, exc: Exception):
    # Generic safe error to avoid leaking internal details (CWE-703).
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# ==========================
# Routes
# ==========================

@app.post("/register", response_model=RegisterResponse, status_code=201, tags=["Authentication"])
async def register(payload: RegisterRequest):
    # Additional validation (best practices)
    # Ensure email and username are unique
    existing_email_user = db_get_user_by_email(payload.email)
    if existing_email_user is not None:
        raise APIError(status_code=400, message="Email already in use or invalid data")

    existing_username_user = db_get_user_by_username(payload.username)
    if existing_username_user is not None:
        raise APIError(status_code=400, message="Email already in use or invalid data")

    # Hash password securely (CWE-522)
    try:
        password_hash = pbkdf2_sha256.hash(payload.password)
    except Exception:
        # If hashing fails for any reason, do not proceed
        raise APIError(status_code=400, message="Email already in use or invalid data")

    created = db_create_user(email=payload.email, username=payload.username, password_hash=password_hash)
    if not created:
        raise APIError(status_code=400, message="Email already in use or invalid data")

    return {"message": "Registration successful"}


@app.post("/login", response_model=LoginResponse, tags=["Authentication"])
async def login(payload: LoginRequest):
    user = db_get_user_by_email(payload.email)
    if user is None:
        # Avoid revealing if the email exists (CWE-522)
        raise APIError(status_code=401, message="Invalid email or password")

    try:
        if not pbkdf2_sha256.verify(payload.password, user["password_hash"]):
            raise APIError(status_code=401, message="Invalid email or password")
    except APIError:
        raise
    except Exception:
        # Error verifying password; treat as authentication failure (CWE-703)
        raise APIError(status_code=401, message="Invalid email or password")

    token = create_access_token(user)
    return {"token": token, "message": "Login successful"}


@app.post("/set_secret", response_model=SetSecretResponse)
async def set_secret(payload: SetSecretRequest, current_user: sqlite3.Row = Depends(get_current_user)):
    # Authorization check: only allow user to set their own secret (CWE-284, CWE-863)
    if payload.username != current_user["username"]:
        raise APIError(status_code=401, message="Invalid authentication token")

    # Validate secret length already via model; still enforce server-side checks.
    secret_text = payload.secret
    if not isinstance(secret_text, str) or secret_text.strip() == "":
        raise APIError(status_code=400, message="Invalid secret content")

    success = db_set_secret_for_user(current_user["id"], secret_text)
    if not success:
        # Database error or failure handled generically
        raise APIError(status_code=500, message="Internal server error")

    return {"message": "Secret has been set successfully"}


@app.get("/get_secret", response_model=GetSecretResponse)
async def get_secret(username: str = Query(..., example="user1"), current_user: sqlite3.Row = Depends(get_current_user)):
    # Authorization check: only allow user to get their own secret
    if username != current_user["username"]:
        raise APIError(status_code=401, message="Invalid authentication token")

    secret = db_get_secret_for_user(current_user["id"])
    if secret is None:
        # If no secret is set yet, return empty string to satisfy response schema
        secret = ""

    return {"secret": secret}


# ==========================
# Startup
# ==========================

@app.on_event("startup")
async def on_startup():
    init_db()


# ==========================
# Main Entry Point
# ==========================

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)