import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from passlib.hash import pbkdf2_sha256
import jwt


# Application configuration
APP_NAME = "Secret Storage"
APP_DESC = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"
DB_PATH = "db.sqlite3"

# Load application secret for JWT
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Generate a random secret if not provided to keep the app runnable.
    # Note: For a production environment, set APP_SECRET via environment variables.
    import secrets as _secrets
    APP_SECRET = _secrets.token_urlsafe(64)

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Token expiration time


# FastAPI app initialization
tags_metadata = [
    {"name": "Authentication", "description": "Operations related to user authentication"},
    {"name": "Secrets", "description": "Operations to manage user secrets"},
]
app = FastAPI(title=APP_NAME, description=APP_DESC, version=APP_VERSION, openapi_tags=tags_metadata)

# Security scheme for Bearer auth; use scheme_name 'bearerAuth' to match OpenAPI schema
http_bearer = HTTPBearer(scheme_name="bearerAuth", auto_error=False)


# Database utilities
def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys=ON;")
    except sqlite3.Error:
        # Ignore pragma error; proceed
        pass
    return conn


def init_db() -> None:
    try:
        conn = get_connection()
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
                user_id INTEGER PRIMARY KEY,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        # Optional indices for performance
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        conn.close()
    except sqlite3.Error as e:
        # Critical: if DB cannot initialize, raise to stop app from running incorrectly
        raise RuntimeError(f"Failed to initialize database: {e}")


@app.on_event("startup")
def on_startup():
    init_db()


# Models
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class SetSecretRequest(BaseModel):
    username: str
    secret: str


# Helper functions
def validate_username(username: str) -> bool:
    # Alphanumeric, underscores, hyphens, 3-32 chars
    if not isinstance(username, str):
        return False
    if len(username) < 3 or len(username) > 32:
        return False
    return re.fullmatch(r"^[A-Za-z0-9_\-]+$", username) is not None


def validate_password_strength(password: str) -> bool:
    # Minimum 8 characters, recommend at least one letter and one number
    if not isinstance(password, str) or len(password) < 8:
        return False
    return True


def create_access_token(user_id: int, username: str, email: str, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(tz=timezone.utc)
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
        "iss": APP_NAME,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})


def get_current_user(credentials: HTTPAuthorizationCredentials = Security(http_bearer)):
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    payload = decode_token(token)
    user_id = payload.get("sub")
    username = payload.get("username")
    email = payload.get("email")
    if not user_id or not username or not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    # Validate against DB to ensure user still exists
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, email, username FROM users WHERE id = ?;", (int(user_id),))
        row = cur.fetchone()
        conn.close()
        if row is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        # Optional consistency check
        if row["username"] != username or row["email"] != email:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        return {"id": row["id"], "email": row["email"], "username": row["username"]}
    except sqlite3.Error:
        # Database error should not leak details
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"})


# Routes
@app.post(
    "/register",
    summary="User registration",
    tags=["Authentication"],
    description="Register a new user with email, username and password.",
    status_code=status.HTTP_201_CREATED,
)
def register(body: RegisterRequest):
    # Validate inputs
    if not validate_username(body.username) or not validate_password_strength(body.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    email = body.email.lower().strip()
    username = body.username.strip()
    password_hash = pbkdf2_sha256.hash(body.password)

    try:
        conn = get_connection()
        cur = conn.cursor()
        # Check uniqueness
        cur.execute("SELECT id FROM users WHERE email = ?;", (email,))
        if cur.fetchone() is not None:
            conn.close()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )
        cur.execute("SELECT id FROM users WHERE username = ?;", (username,))
        if cur.fetchone() is not None:
            conn.close()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )

        now_iso = datetime.now(tz=timezone.utc).isoformat()
        cur.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (email, username, password_hash, now_iso),
        )
        conn.close()
        return {"message": "Registration successful"}
    except sqlite3.Error:
        # Handle unexpected DB errors gracefully
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"})


@app.post(
    "/login",
    summary="User login",
    tags=["Authentication"],
    description="Authenticate a user with email and password.",
)
def login(body: LoginRequest):
    email = body.email.lower().strip()
    password = body.password

    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?;", (email,))
        row = cur.fetchone()
        conn.close()
        if row is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
        password_hash = row["password_hash"]
        if not pbkdf2_sha256.verify(password, password_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
        token = create_access_token(user_id=row["id"], username=row["username"], email=row["email"])
        return {"token": token, "message": "Login successful"}
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"})


@app.post(
    "/set_secret",
    summary="Set secret",
    tags=["Secrets"],
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(body: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    # Authorization: ensure the username in the body matches the token's username
    if not validate_username(body.username):
        # Avoid leaking info; treat as implicit auth failure
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    if body.username != current_user["username"]:
        # Do not allow setting secret for another user
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    # Basic bounds check for secret size to prevent abuse
    secret_text = body.secret
    if not isinstance(secret_text, str):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Invalid data"})
    if len(secret_text) > 8192:
        # Prevent excessively large secrets
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Invalid data"})

    try:
        conn = get_connection()
        cur = conn.cursor()
        now_iso = datetime.now(tz=timezone.utc).isoformat()
        # Upsert secret for the user using ON CONFLICT
        cur.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret=excluded.secret,
                updated_at=excluded.updated_at;
            """,
            (current_user["id"], secret_text, now_iso),
        )
        conn.close()
        return {"message": "Secret has been set successfully"}
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"})


@app.get(
    "/get_secret",
    summary="Get secret",
    tags=["Secrets"],
    description="Retrieve a secret based on the provided username.",
)
def get_secret(username: str, current_user: dict = Depends(get_current_user)):
    if not validate_username(username):
        # Treat invalid username as unauthorized to avoid information disclosure
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    if username != current_user["username"]:
        # Do not allow reading secret for another user
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT secret FROM secrets WHERE user_id = ?;", (current_user["id"],))
        row = cur.fetchone()
        conn.close()
        # If no secret stored, return empty string to adhere to schema (200 on success)
        secret_text = row["secret"] if row is not None else ""
        return {"secret": secret_text}
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"})


if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)