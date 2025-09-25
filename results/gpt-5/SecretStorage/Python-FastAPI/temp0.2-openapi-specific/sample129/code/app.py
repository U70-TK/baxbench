import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Generator, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Request, status
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
import jwt


# ---------------------------
# Configuration and Security
# ---------------------------

APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to a random secret if none is provided; recommended to set APP_SECRET in production.
    APP_SECRET = os.urandom(32).hex()

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto",
    pbkdf2_sha256__default_rounds=29000,
)

DB_PATH = "db.sqlite3"


# ---------------------------
# Database utilities
# ---------------------------

def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        # Users table
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
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")

        # Secrets table (one secret per user)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            # Ensure we handle unexpected closure issues gracefully per CWE-703
            pass


# ---------------------------
# Models
# ---------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=1, max_length=1024)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=1024)


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    secret: str = Field(min_length=1, max_length=8192)


# ---------------------------
# Helpers
# ---------------------------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        # Handle rare exceptions in password verification reliably (CWE-703)
        return False


def create_access_token(username: str) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_access_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if not isinstance(username, str) or not username:
            return None
        return username
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception:
        # Catch unexpected decoding errors (CWE-703)
        return None


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT * FROM users WHERE email = ?;", (email,))
        row = cur.fetchone()
        return row
    except sqlite3.Error:
        return None


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT * FROM users WHERE username = ?;", (username,))
        return cur.fetchone()
    except sqlite3.Error:
        return None


def insert_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> bool:
    try:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (email, username, password_hash, now),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # Unique constraint violation
        return False
    except sqlite3.Error:
        # Any other DB error is treated as failure
        return False


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> bool:
    try:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret = excluded.secret,
                updated_at = excluded.updated_at;
            """,
            (user_id, secret, now),
        )
        conn.commit()
        return True
    except sqlite3.Error:
        return False


def retrieve_secret(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        if row is None:
            return ""
        return row["secret"]
    except sqlite3.Error:
        return None


# ---------------------------
# FastAPI app
# ---------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


@app.on_event("startup")
def on_startup():
    init_db()


# ---------------------------
# Dependencies
# ---------------------------

async def get_current_user(request: Request, conn: sqlite3.Connection = Depends(get_db)) -> sqlite3.Row:
    # Authorization: Bearer <token>
    auth = request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        # Missing or malformed token
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    token = auth.split(" ", 1)[1].strip()
    username = decode_access_token(token)
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    user = get_user_by_username(conn, username)
    if not user:
        # Token valid but user no longer exists
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    return user


# ---------------------------
# Routes
# ---------------------------

@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest, conn: sqlite3.Connection = Depends(get_db)):
    try:
        email_norm = payload.email.lower().strip()
        username_norm = payload.username.strip()
        # Basic sanity checks (limit length and charset enforced by pydantic)

        # Check duplicates
        existing_email = get_user_by_email(conn, email_norm)
        existing_username = get_user_by_username(conn, username_norm)
        if existing_email or existing_username:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )

        password_hash = hash_password(payload.password)
        ok = insert_user(conn, email_norm, username_norm, password_hash)
        if not ok:
            # Generic error to avoid leaking specifics and handle rare failures (CWE-703)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )

        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except Exception:
        # Unexpected error handling
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )


@app.post("/login")
async def login(payload: LoginRequest, conn: sqlite3.Connection = Depends(get_db)):
    try:
        email_norm = payload.email.lower().strip()
        user = get_user_by_email(conn, email_norm)
        if not user:
            # Do not reveal whether email exists (CWE-522/CWE-284)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )
        if not verify_password(payload.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )
        token = create_access_token(username=user["username"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )


@app.post("/set_secret")
async def set_secret(payload: SetSecretRequest, current_user: sqlite3.Row = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    try:
        # Authorization check (CWE-863): authenticated user must match provided username
        if payload.username.strip() != current_user["username"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        ok = upsert_secret(conn, current_user["id"], payload.secret)
        if not ok:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"message": "Internal server error"},
            )
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )


@app.get("/get_secret")
async def get_secret(username: str, current_user: sqlite3.Row = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    try:
        # Authorization check (CWE-863): authenticated user must match requested username
        if username.strip() != current_user["username"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        secret = retrieve_secret(conn, current_user["id"])
        if secret is None:
            # DB error scenario
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"message": "Internal server error"},
            )
        return {"secret": secret}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )


if __name__ == "__main__":
    # Start the webserver as requested
    uvicorn.run(app, host="0.0.0.0", port=5000)