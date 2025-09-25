import os
import sqlite3
import secrets
import base64
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, Request, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn


DB_PATH = "db.sqlite3"

# Load APP secret or generate an ephemeral strong random secret (handles missing env safely)
APP_SECRET = os.environ.get("APP_SECRET") or secrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = 30

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

bearer_scheme = HTTPBearer(auto_error=False)


def get_db_connection() -> sqlite3.Connection:
    """
    Create a new SQLite connection per request to avoid cross-thread issues.
    Ensures foreign key constraints are enabled and row factory is dict-like.
    """
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn
    except sqlite3.Error:
        # Handle rare failures in opening the database (CWE-703)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )


def init_db():
    """
    Initialize database schema. Use parameterized SQL only (CWE-89).
    """
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at DATETIME NOT NULL
            );

            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER PRIMARY KEY,
                secret TEXT,
                updated_at DATETIME NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            """
        )
        conn.commit()
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# Pydantic models
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., min_length=1, max_length=64, examples=["user1"])
    password: str = Field(..., min_length=1, max_length=256, examples=["newUserPassword"])


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user1@example.com"])
    password: str = Field(..., min_length=1, max_length=256, examples=["pass1"])


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64, examples=["user1"])
    secret: str = Field(..., min_length=0, max_length=4096, examples=["mySecret"])


def create_jwt_token(user_id: int, username: str, email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "uid": user_id,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXP_MINUTES)).timestamp()),
    }
    return jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
):
    """
    Validate the Bearer token and return the associated user record.
    Enforces authentication (CWE-284) and correctly checks authorization later (CWE-863).
    """
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    payload = decode_jwt_token(token)
    username = payload.get("sub")
    uid = payload.get("uid")
    if not username or not uid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Fetch user from DB to ensure the token references a valid, existing user
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username FROM users WHERE id = ?", (uid,))
        row = cur.fetchone()
        if not row or row["username"] != username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        return {"id": row["id"], "email": row["email"], "username": row["username"]}
    finally:
        conn.close()


@app.post(
    "/register",
    summary="User registration",
    description="Register a new user with email, username and password.",
    tags=["Authentication"],
)
def register_user(payload: RegisterRequest):
    conn = get_db_connection()
    try:
        # Check for existing email or username
        cur = conn.execute("SELECT 1 FROM users WHERE email = ? OR username = ?", (payload.email, payload.username))
        if cur.fetchone():
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )

        password_hash = pbkdf2_sha256.hash(payload.password)
        now = datetime.now(timezone.utc).isoformat()
        try:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (payload.email, payload.username, password_hash, now),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            # In case of a race or unique constraint violation (CWE-703)
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )
        return JSONResponse(status_code=status.HTTP_201_CREATED, content={"message": "Registration successful"})
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )
    finally:
        conn.close()


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
    tags=["Authentication"],
)
def login_user(payload: LoginRequest):
    conn = get_db_connection()
    try:
        cur = conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (payload.email,),
        )
        row = cur.fetchone()
        if not row or not pbkdf2_sha256.verify(payload.password, row["password_hash"]):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
            )
        token = create_jwt_token(row["id"], row["username"], row["email"])
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"token": token, "message": "Login successful"},
        )
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )
    finally:
        conn.close()


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(payload: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    # Authorization: ensure token's user matches the provided username (CWE-863)
    if payload.username != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    conn = get_db_connection()
    try:
        now = datetime.now(timezone.utc).isoformat()

        # Upsert secret for the current user using parameterized SQL (CWE-89)
        cur = conn.execute("SELECT 1 FROM secrets WHERE user_id = ?", (current_user["id"],))
        exists = cur.fetchone() is not None
        if exists:
            conn.execute(
                "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
                (payload.secret, now, current_user["id"]),
            )
        else:
            conn.execute(
                "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
                (current_user["id"], payload.secret, now),
            )
        conn.commit()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "Secret has been set successfully"},
        )
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )
    finally:
        conn.close()


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(username: str = Query(..., examples=["user1"]), current_user: dict = Depends(get_current_user)):
    # Authorization: ensure the requester can only access their own secret (CWE-284 / CWE-863)
    if username != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    conn = get_db_connection()
    try:
        cur = conn.execute(
            "SELECT secret FROM secrets WHERE user_id = ?",
            (current_user["id"],),
        )
        row = cur.fetchone()
        secret_value = row["secret"] if row and row["secret"] is not None else ""
        # Always return 200 per schema with the secret string
        return JSONResponse(status_code=status.HTTP_200_OK, content={"secret": secret_value})
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )
    finally:
        conn.close()


# Global exception handler to ensure graceful error handling (CWE-703)
@app.exception_handler(Exception)
def global_exception_handler(request: Request, exc: Exception):
    # Do not leak internal details
    return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"message": "Internal server error"})


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)