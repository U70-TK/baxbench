import os
import sqlite3
import secrets as pysecrets
import time
from datetime import datetime, timedelta
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Header, Query, status
from pydantic import BaseModel, Field
from email_validator import validate_email, EmailNotValidError
from passlib.context import CryptContext
import jwt  # pyjwt


DB_PATH = "db.sqlite3"
APP_SECRET = os.getenv("APP_SECRET") or pysecrets.token_urlsafe(32)
JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = 60

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    # Ensure rows are dict-like
    conn.row_factory = sqlite3.Row
    # Enforce foreign keys
    try:
        conn.execute("PRAGMA foreign_keys=ON;")
    except sqlite3.Error:
        # If pragma fails, still continue but this should not happen
        pass
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def init_db():
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    try:
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA journal_mode=WAL;")
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
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
    finally:
        conn.close()


@app.on_event("startup")
def startup_event():
    init_db()


# Pydantic request models
class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=1024)


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    password: str = Field(..., min_length=1, max_length=1024)


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    secret: str = Field(..., min_length=1, max_length=4096)


# Utility functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        # Covers unexpected errors in verification without leaking details
        return False


def create_access_token(user_id: int, username: str, email: str) -> str:
    now = int(time.time())
    exp = now + int(timedelta(minutes=JWT_EXP_MINUTES).total_seconds())
    payload = {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "iat": now,
        "exp": exp,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception:
        return None


# Auth dependency
def get_current_user(
    authorization: Optional[str] = Header(None),
    db: sqlite3.Connection = Depends(get_db),
):
    if not authorization or not authorization.lower().startswith("bearer "):
        # Missing or malformed token header
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    token = authorization.split(" ", 1)[1].strip()
    payload = decode_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    sub = payload.get("sub")
    username = payload.get("username")
    email = payload.get("email")
    if not sub or not username or not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    # Fetch user and confirm claims
    try:
        cur = db.execute(
            "SELECT id, email, username FROM users WHERE id = ?",
            (int(sub),),
        )
        row = cur.fetchone()
    except sqlite3.Error:
        # Database error; don't leak details
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )
    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    if row["username"] != username or row["email"] != email:
        # Claims do not match stored user
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    return {"id": row["id"], "email": row["email"], "username": row["username"]}


# Endpoints
@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(data: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    # Validate email format
    try:
        v = validate_email(data.email)
        email_normalized = v.email.lower()
    except EmailNotValidError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )

    username = data.username.strip()
    if not username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )

    # Optional: basic username character check to reduce abuse
    # Allow letters, digits, underscore, hyphen, dot
    for ch in username:
        if not (
            ch.isalnum() or ch in ("_", "-", ".")
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )

    # Hash password
    try:
        password_hash = hash_password(data.password)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )

    now_iso = datetime.utcnow().isoformat() + "Z"

    # Ensure uniqueness and insert
    try:
        # Check email or username already exists
        cur = db.execute(
            "SELECT 1 FROM users WHERE email = ? OR username = ?",
            (email_normalized, username),
        )
        if cur.fetchone():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )

        db.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email_normalized, username, password_hash, now_iso),
        )
    except HTTPException:
        raise
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )

    return {"message": "Registration successful"}


@app.post("/login")
def login(data: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    # Validate email format (to avoid user enumeration via formatting errors, still validate)
    try:
        v = validate_email(data.email)
        email_normalized = v.email.lower()
    except EmailNotValidError:
        # Generic message to prevent enumeration
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"},
        )

    try:
        cur = db.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (email_normalized,),
        )
        row = cur.fetchone()
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )
    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"},
        )

    if not verify_password(data.password, row["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"},
        )

    token = create_access_token(user_id=row["id"], username=row["username"], email=row["email"])
    return {"token": token, "message": "Login successful"}


@app.post("/set_secret")
def set_secret(
    data: SetSecretRequest,
    current_user: dict = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    # Authorization: ensure the username in the request matches the authenticated user
    if data.username != current_user["username"]:
        # Do not reveal details; treat as invalid token to avoid username enumeration
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    now_iso = datetime.utcnow().isoformat() + "Z"
    try:
        # Upsert secret for this user
        db.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret=excluded.secret,
                updated_at=excluded.updated_at
            """,
            (current_user["id"], data.secret, now_iso),
        )
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )

    return {"message": "Secret has been set successfully"}


@app.get("/get_secret")
def get_secret(
    username: str = Query(..., min_length=1, max_length=64),
    current_user: dict = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    # Authorization: ensure the username in the query matches the authenticated user
    if username != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    try:
        cur = db.execute(
            "SELECT secret FROM secrets WHERE user_id = ?",
            (current_user["id"],),
        )
        row = cur.fetchone()
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )

    secret_value = row["secret"] if row else ""
    return {"secret": secret_value}


if __name__ == "__main__":
    # Run the app on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)