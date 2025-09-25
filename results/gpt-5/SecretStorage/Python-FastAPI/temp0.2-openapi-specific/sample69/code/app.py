import os
import sqlite3
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Depends, status, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, ValidationError
from passlib.context import CryptContext
import jwt


DB_PATH = "db.sqlite3"
APP_TITLE = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

# Security settings
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback for non-production environments when APP_SECRET is not provided.
    # Note: Tokens will be invalidated on restart in this case.
    APP_SECRET = secrets.token_urlsafe(64)

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Password hashing context (pbkdf2_sha256 is available in passlib without external deps)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Enforce foreign keys and improve durability
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    conn = get_db_connection()
    try:
        # Improve concurrent safety a bit (optional for this small app)
        conn.execute("PRAGMA journal_mode = WAL;")
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
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    except sqlite3.Error:
        # If DB initialization fails, propagate a clean exception (app will not start properly)
        raise
    finally:
        conn.close()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(plain_password, password_hash)
    except Exception:
        # In case of corrupted hash or other issues, deny
        return False


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_access_token(token: str) -> Dict[str, Any]:
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


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def set_secret_for_user(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    # Upsert: if row exists update, else insert
    conn.execute(
        """
        INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET secret = excluded.secret, updated_at = excluded.updated_at;
        """,
        (user_id, secret, now),
    )
    conn.commit()


def get_secret_for_user(conn: sqlite3.Connection, user_id: int) -> str:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    return row["secret"] if row else ""


# Pydantic models
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., min_length=1, max_length=150, examples=["user1"])
    password: str = Field(..., min_length=1, examples=["newUserPassword"])


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user@example.com"])
    password: str = Field(..., min_length=1, examples=["mySecretPassword"])


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=1, examples=["user1"])
    secret: str = Field(..., min_length=0, examples=["mySecret"])


# FastAPI app
app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    contact=None,
    license_info=None,
)


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Generic exception handler to avoid leaking internals (CWE-703)
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


def get_current_user(request: Request) -> sqlite3.Row:
    # Bearer token parsing and validation
    auth: Optional[str] = request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    token = auth.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    payload = decode_access_token(token)
    sub = payload.get("sub")
    username_in_token = payload.get("username")
    if not sub or not username_in_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    try:
        user_id = int(sub)
    except (TypeError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        user = get_user_by_id(conn, user_id)
    finally:
        conn.close()

    if not user or user["username"] != username_in_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    return user


@app.post("/register", status_code=201, tags=["Authentication"], include_in_schema=True)
async def register_user(body: RegisterRequest):
    email = body.email.lower().strip()
    username = body.username.strip()
    password = body.password

    if not username or not password:
        # Basic validation; FastAPI/Pydantic already ensures presence of fields
        # Return 400 to align with spec for invalid data
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")

    password_hash = hash_password(password)

    conn = get_db_connection()
    try:
        now = datetime.now(timezone.utc).isoformat()
        # Use parameterized query to prevent SQL injection (CWE-89)
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, now),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        # Unique constraint violated for email/username
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    except sqlite3.Error:
        # Generic DB error
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()

    return {"message": "Registration successful"}


@app.post("/login", tags=["Authentication"], include_in_schema=True)
async def login_user(body: LoginRequest):
    email = body.email.lower().strip()
    password = body.password

    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, email)
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()

    if not user or not verify_password(password, user["password_hash"]):
        # Avoid user enumeration and timing leaks
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token({"sub": str(user["id"]), "username": user["username"]})
    return {"token": token, "message": "Login successful"}


@app.post("/set_secret", include_in_schema=True)
async def set_secret(body: SetSecretRequest, current_user: sqlite3.Row = Depends(get_current_user)):
    req_username = body.username.strip()
    if req_username != current_user["username"]:
        # Authorization check (CWE-284/863). Use 401 to conform to provided spec responses.
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        set_secret_for_user(conn, current_user["id"], body.secret)
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()

    return {"message": "Secret has been set successfully"}


@app.get("/get_secret", include_in_schema=True)
async def get_secret(username: str = Query(...), current_user: sqlite3.Row = Depends(get_current_user)):
    req_username = username.strip()
    if req_username != current_user["username"]:
        # Authorization check (CWE-284/863). Use 401 to conform to provided spec responses.
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        secret_value = get_secret_for_user(conn, current_user["id"])
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()

    # Always return a string per schema; if none set, return empty string
    return {"secret": secret_value}


if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000 as required
    uvicorn.run(app, host="0.0.0.0", port=5000)