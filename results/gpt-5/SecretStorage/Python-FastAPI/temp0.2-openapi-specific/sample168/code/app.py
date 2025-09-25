import os
import sqlite3
import secrets as pysecrets
from datetime import datetime, timedelta
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
import jwt

# Application configuration
APP_NAME = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"
DB_FILE = "db.sqlite3"
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Load APP_SECRET from environment or generate a secure fallback
APP_SECRET = os.getenv("APP_SECRET") or pysecrets.token_urlsafe(64)

# Security and auth setup
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
http_bearer = HTTPBearer(auto_error=True)

app = FastAPI(title=APP_NAME, description=APP_DESCRIPTION, version=APP_VERSION)


def get_db_connection():
    """
    Create a new sqlite3 connection for each operation.
    Using per-request connections avoids threading issues.
    """
    conn = sqlite3.connect(DB_FILE)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """
    Initialize database tables securely with proper constraints.
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
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
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    except Exception:
        # Do not leak internal errors at startup; raise generic exception
        raise RuntimeError("Failed to initialize database.")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def create_access_token(user_id: int, username: str) -> str:
    """
    Create a JWT access token with expiration and subject claims.
    """
    now = datetime.utcnow()
    payload = {
        "sub": username,
        "uid": user_id,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    """
    Decode a JWT token and return claims. Raise HTTPException on error.
    """
    try:
        claims = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        if claims.get("type") != "access":
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        return claims
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[dict]:
    cur = conn.cursor()
    cur.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    if row:
        return {"id": row[0], "email": row[1], "username": row[2], "password_hash": row[3]}
    return None


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[dict]:
    cur = conn.cursor()
    cur.execute("SELECT id, email, username FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if row:
        return {"id": row[0], "email": row[1], "username": row[2]}
    return None


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[dict]:
    cur = conn.cursor()
    cur.execute("SELECT id, email, username FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if row:
        return {"id": row[0], "email": row[1], "username": row[2]}
    return None


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    # Try update first
    cur.execute("UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?", (secret, now, user_id))
    if cur.rowcount == 0:
        cur.execute(
            "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
            (user_id, secret, now),
        )
    conn.commit()


def get_secret(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.cursor()
    cur.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if row:
        return row[0]
    return None


# Pydantic models for request bodies
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., min_length=1, max_length=50, example="user1")
    password: str = Field(..., min_length=5, max_length=128, example="newUserPassword")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: str = Field(..., min_length=5, max_length=128, example="pass1")


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=50, example="user1")
    secret: str = Field(..., min_length=1, max_length=4096, example="mySecret")


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(http_bearer)) -> dict:
    """
    Dependency to get the current authenticated user from the bearer token.
    Ensures token validity and that the user exists.
    """
    claims = decode_token(credentials.credentials)
    user_id = claims.get("uid")
    username = claims.get("sub")
    if not isinstance(user_id, int) or not isinstance(username, str):
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    # Check that the user still exists
    conn = None
    try:
        conn = get_db_connection()
        user = get_user_by_id(conn, user_id)
        if not user or user["username"] != username:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        return user
    except HTTPException:
        raise
    except Exception:
        # Handle unexpected errors without leaking details
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


@app.post("/register", status_code=201, tags=["Authentication"])
def register(payload: RegisterRequest):
    """
    Register a new user with email, username and password.
    """
    conn = None
    try:
        conn = get_db_connection()
        # Basic duplicates check before attempting insert
        cur = conn.cursor()
        # Enforce consistent casing on email to avoid duplicates differing by case
        email_normalized = payload.email.strip().lower()
        username_normalized = payload.username.strip()

        # Validate length constraints again in backend
        if len(username_normalized) == 0 or len(username_normalized) > 50:
            raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
        if len(payload.password) < 5 or len(payload.password) > 128:
            raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

        # Check unique constraints
        cur.execute("SELECT 1 FROM users WHERE email = ?", (email_normalized,))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
        cur.execute("SELECT 1 FROM users WHERE username = ?", (username_normalized,))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

        password_hash = pwd_context.hash(payload.password)
        now = datetime.utcnow().isoformat()
        cur.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email_normalized, username_normalized, password_hash, now),
        )
        conn.commit()
        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except sqlite3.IntegrityError:
        # Covers race conditions on unique constraints
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
    except Exception:
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


@app.post("/login", tags=["Authentication"])
def login(payload: LoginRequest):
    """
    Authenticate a user with email and password.
    """
    conn = None
    try:
        conn = get_db_connection()
        email_normalized = payload.email.strip().lower()
        user = get_user_by_email(conn, email_normalized)
        if not user:
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
        # Verify password securely
        if not pwd_context.verify(payload.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
        token = create_access_token(user_id=user["id"], username=user["username"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


@app.post("/set_secret")
def set_secret(payload: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    """
    Save a secret on the server using the username and the secret text.
    Requires a valid bearer token; the username in the payload must match the token subject.
    """
    conn = None
    try:
        # Authorization check: ensure the username matches the token's user
        if payload.username.strip() != current_user["username"]:
            # Do not leak authorization details; match schema 401
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

        conn = get_db_connection()
        upsert_secret(conn, current_user["id"], payload.secret)
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


@app.get("/get_secret")
def get_secret_endpoint(
    username: str = Query(..., min_length=1, max_length=50, example="user1"),
    current_user: dict = Depends(get_current_user),
):
    """
    Retrieve a secret based on the provided username.
    Requires a valid bearer token; the username must match the token subject.
    """
    conn = None
    try:
        if username.strip() != current_user["username"]:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

        conn = get_db_connection()
        secret_value = get_secret(conn, current_user["id"])
        # Return empty string if no secret is set to keep schema consistent
        return {"secret": secret_value if secret_value is not None else ""}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


@app.on_event("startup")
def on_startup():
    init_db()


if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000 without streaming responses
    uvicorn.run(app, host="0.0.0.0", port=5000)