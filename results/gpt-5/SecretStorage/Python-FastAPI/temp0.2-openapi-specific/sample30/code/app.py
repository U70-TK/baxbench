import os
import re
import sqlite3
import base64
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Security, Query
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, field_validator
from passlib.hash import pbkdf2_sha256
import jwt  # pyjwt

DB_PATH = "db.sqlite3"

# Application setup
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Security setup
http_bearer = HTTPBearer(auto_error=False)

def get_app_secret() -> str:
    env_secret = os.getenv("APP_SECRET")
    if env_secret and len(env_secret) >= 16:
        return env_secret
    # Fallback: ephemeral secret (not persistent). Strong random string.
    return base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")


APP_SECRET = get_app_secret()
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60


# Database helpers and lifecycle
def get_db():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
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
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.on_event("startup")
def on_startup():
    init_db()


# Models
USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,50}$")


class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., min_length=3, max_length=50, examples=["user1"])
    password: str = Field(..., min_length=8, max_length=128, examples=["newUserPassword"])

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str):
        if not USERNAME_REGEX.fullmatch(v):
            raise ValueError("Username must be 3-50 characters and include only letters, numbers, and underscores")
        return v


class RegisterResponse(BaseModel):
    message: str = "Registration successful"


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user@example.com"])
    password: str = Field(..., min_length=1, max_length=128, examples=["mySecretPassword"])


class LoginResponse(BaseModel):
    token: str
    message: str = "Login successful"


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, examples=["user1"])
    secret: str = Field(..., min_length=0, max_length=4096, examples=["mySecret"])

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str):
        if not USERNAME_REGEX.fullmatch(v):
            raise ValueError("Invalid username format")
        return v


class SetSecretResponse(BaseModel):
    message: str = "Secret has been set successfully"


class GetSecretResponse(BaseModel):
    secret: str


# Password utilities
def hash_password(plain_password: str) -> str:
    # Passlib pbkdf2_sha256 includes a random salt and is suitable for password hashing
    return pbkdf2_sha256.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(plain_password, password_hash)
    except Exception:
        return False


# JWT utilities
def create_access_token(*, user_id: int, username: str, email: str, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta if expires_delta else timedelta(minutes=JWT_EXPIRE_MINUTES))
    jti = base64.urlsafe_b64encode(pysecrets.token_bytes(16)).decode("utf-8")
    to_encode = {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


# Auth dependency
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(http_bearer),
    db: sqlite3.Connection = Depends(get_db),
):
    if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    token = credentials.credentials
    payload = decode_token(token)
    # Fetch user and ensure still exists
    user_id = payload.get("sub")
    username = payload.get("username")
    if not user_id or not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    try:
        cur = db.execute("SELECT id, email, username FROM users WHERE id = ? AND username = ?;", (user_id, username))
        row = cur.fetchone()
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    return {"id": row["id"], "email": row["email"], "username": row["username"]}


# Error handlers to avoid leaking details (CWE-703)
@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc):
    # Generic 500 without internal details
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    # Return 400 for validation issues
    return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})


# Routes
@app.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
)
def register(payload: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    # Ensure email and username uniqueness and insert a new user with a hashed password
    password_hash = hash_password(payload.password)
    try:
        db.execute(
            "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?);",
            (payload.email, payload.username, password_hash),
        )
        db.commit()
    except sqlite3.IntegrityError:
        # Unique constraint violated (email or username)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    return {"message": "Registration successful"}


@app.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    tags=["Authentication"],
)
def login(payload: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    try:
        cur = db.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?;",
            (payload.email,),
        )
        user = cur.fetchone()
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    token = create_access_token(user_id=user["id"], username=user["username"], email=user["email"])
    return {"token": token, "message": "Login successful"}


@app.post(
    "/set_secret",
    response_model=SetSecretResponse,
    status_code=status.HTTP_200_OK,
)
def set_secret(
    payload: SetSecretRequest,
    current_user: dict = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    # Authorization check: token user must match provided username (CWE-863)
    if current_user["username"] != payload.username:
        # Do not leak whether the username exists
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    # Obtain user_id from current user to avoid trusting request body
    user_id = current_user["id"]
    try:
        # Upsert secret securely (CWE-89)
        db.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=CURRENT_TIMESTAMP;
            """,
            (user_id, payload.secret),
        )
        db.commit()
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    return {"message": "Secret has been set successfully"}


@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
    status_code=status.HTTP_200_OK,
)
def get_secret(
    username: str = Query(..., min_length=3, max_length=50, examples=["user1"]),
    current_user: dict = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    if not USERNAME_REGEX.fullmatch(username):
        # Basic input validation
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid authentication token")

    # Authorization: user can only fetch their own secret
    if current_user["username"] != username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    try:
        cur = db.execute(
            """
            SELECT s.secret
            FROM users u
            LEFT JOIN secrets s ON s.user_id = u.id
            WHERE u.username = ?;
            """,
            (username,),
        )
        row = cur.fetchone()
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

    secret_text = row["secret"] if row and row["secret"] is not None else ""
    return {"secret": secret_text}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)