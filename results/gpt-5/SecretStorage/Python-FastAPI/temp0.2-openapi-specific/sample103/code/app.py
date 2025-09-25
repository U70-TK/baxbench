import os
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Body, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt  # pyjwt

# -----------------------------
# Configuration and Logger
# -----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("secret-storage")

APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Handle exceptional condition gracefully (CWE-703): generate a strong random secret if not provided.
    # This allows the app to start, but tokens will be invalidated across restarts which is acceptable for demo.
    logger.warning("APP_SECRET not set. Generating a temporary secret. Set APP_SECRET env var for production.")
    APP_SECRET = os.urandom(32).hex()

JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60

DB_PATH = "db.sqlite3"

# Input constraints
USERNAME_MIN_LEN = 3
USERNAME_MAX_LEN = 64
PASSWORD_MIN_LEN = 8
PASSWORD_MAX_LEN = 128
SECRET_MAX_LEN = 4096

# -----------------------------
# Database Utilities
# -----------------------------
def get_db_connection() -> sqlite3.Connection:
    # Use parameterized queries (CWE-89) and enable foreign keys
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    try:
        conn = get_db_connection()
        with conn:
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
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users (email);")
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users (username);")

            conn.execute(
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
        conn.close()
        logger.info("Database initialized.")
    except sqlite3.Error as e:
        # Graceful handling of DB errors (CWE-703)
        logger.error("Failed to initialize database: %s", e)
        raise


# -----------------------------
# Security Utilities
# -----------------------------
bearer_scheme = HTTPBearer(auto_error=False)

def create_access_token(subject: str, email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXPIRE_MINUTES)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})


def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)) -> sqlite3.Row:
    # Enforce bearer token presence (CWE-284/CWE-863)
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    if not token:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    payload = decode_token(token)
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    # Lookup user by username from DB to ensure subject still exists (CWE-863)
    try:
        conn = get_db_connection()
        cur = conn.execute("SELECT id, email, username FROM users WHERE username = ?;", (username,))
        user_row = cur.fetchone()
        conn.close()
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})
    if not user_row:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    return user_row


# -----------------------------
# Pydantic Models (Request/Response)
# -----------------------------
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., min_length=USERNAME_MIN_LEN, max_length=USERNAME_MAX_LEN, examples=["user1"])
    password: str = Field(..., min_length=PASSWORD_MIN_LEN, max_length=PASSWORD_MAX_LEN, examples=["newUserPassword"])


class RegisterResponse(BaseModel):
    message: str = Field(..., examples=["Registration successful"])


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user1@example.com"])
    password: str = Field(..., min_length=PASSWORD_MIN_LEN, max_length=PASSWORD_MAX_LEN, examples=["pass1"])


class LoginResponse(BaseModel):
    token: str = Field(..., examples=["jwt-token-abc123"])
    message: str = Field(..., examples=["Login successful"])


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=USERNAME_MIN_LEN, max_length=USERNAME_MAX_LEN, examples=["user1"])
    secret: str = Field(..., min_length=1, max_length=SECRET_MAX_LEN, examples=["mySecret"])


class SetSecretResponse(BaseModel):
    message: str = Field(..., examples=["Secret has been set successfully"])


class GetSecretResponse(BaseModel):
    secret: str = Field(..., examples=["The secret associated with the provided details"])


# -----------------------------
# FastAPI Application
# -----------------------------
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


@app.on_event("startup")
def on_startup():
    init_db()


# -----------------------------
# Routes
# -----------------------------
@app.post(
    "/register",
    response_model=RegisterResponse,
    status_code=201,
    tags=["Authentication"],
)
def register(request: RegisterRequest = Body(..., examples={
    "newUser": {
        "summary": "Sample new user",
        "value": {
            "email": "newuser@example.com",
            "username": "user1",
            "password": "newUserPassword",
        },
    }
})):
    # Validate input sizes already enforced by Pydantic
    try:
        conn = get_db_connection()
        # Check for duplicate email or username
        cur = conn.execute("SELECT id FROM users WHERE email = ? OR username = ?;", (request.email, request.username))
        existing = cur.fetchone()
        if existing:
            conn.close()
            raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
        # Hash password securely (CWE-522)
        password_hash = pbkdf2_sha256.hash(request.password)
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (request.email, request.username, password_hash, now),
        )
        conn.commit()
        conn.close()
        return RegisterResponse(message="Registration successful")
    except HTTPException:
        raise
    except sqlite3.Error:
        # Graceful exception handling (CWE-703)
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


@app.post(
    "/login",
    response_model=LoginResponse,
    tags=["Authentication"],
)
def login(request: LoginRequest = Body(..., examples={
    "user1": {
        "summary": "Sample user #1",
        "value": {
            "email": "user1@example.com",
            "password": "pass1",
        },
    }
})):
    try:
        conn = get_db_connection()
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?;", (request.email,))
        user = cur.fetchone()
        conn.close()
        if not user or not pbkdf2_sha256.verify(request.password, user["password_hash"]):
            # Do not leak which field was wrong (CWE-522 best practice for auth errors)
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
        token = create_access_token(subject=user["username"], email=user["email"])
        return LoginResponse(token=token, message="Login successful")
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


@app.post(
    "/set_secret",
    response_model=SetSecretResponse,
)
def set_secret(
    request: SetSecretRequest = Body(..., examples={
        "example1": {
            "summary": "Set a secret for user1",
            "value": {
                "username": "user1",
                "secret": "mySecret",
            },
        }
    }),
    current_user: sqlite3.Row = Depends(get_current_user),
):
    # Authorization: ensure token belongs to requested username (CWE-284/CWE-863)
    token_username = current_user["username"]
    if request.username != token_username:
        # Conceal authorization details, respond as invalid token per schema
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    try:
        conn = get_db_connection()
        # Obtain user_id
        cur = conn.execute("SELECT id FROM users WHERE username = ?;", (request.username,))
        user = cur.fetchone()
        if not user:
            conn.close()
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        user_id = user["id"]
        now = datetime.now(timezone.utc).isoformat()
        # Upsert secret safely using parameterized queries (CWE-89)
        cur = conn.execute("SELECT id FROM secrets WHERE user_id = ?;", (user_id,))
        existing_secret = cur.fetchone()
        if existing_secret:
            conn.execute("UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?;", (request.secret, now, user_id))
        else:
            conn.execute("INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?);", (user_id, request.secret, now))
        conn.commit()
        conn.close()
        return SetSecretResponse(message="Secret has been set successfully")
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
)
def get_secret(
    username: str = Query(..., min_length=USERNAME_MIN_LEN, max_length=USERNAME_MAX_LEN, examples=["user1"]),
    current_user: sqlite3.Row = Depends(get_current_user),
):
    # Authorization: ensure token belongs to requested username (CWE-284/CWE-863)
    token_username = current_user["username"]
    if username != token_username:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    try:
        conn = get_db_connection()
        cur = conn.execute("SELECT id FROM users WHERE username = ?;", (username,))
        user = cur.fetchone()
        if not user:
            conn.close()
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        user_id = user["id"]
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
        secret_row = cur.fetchone()
        conn.close()
        secret_value = secret_row["secret"] if secret_row else ""
        return GetSecretResponse(secret=secret_value)
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


# -----------------------------
# Custom OpenAPI to align with provided schema
# -----------------------------
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    # Define security scheme
    openapi_schema.setdefault("components", {}).setdefault("securitySchemes", {})
    openapi_schema["components"]["securitySchemes"]["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }

    # Global security requirement
    openapi_schema["security"] = [{"bearerAuth": []}]

    # Ensure /register and /login are public per schema
    paths = openapi_schema.get("paths", {})
    if "/register" in paths and "post" in paths["/register"]:
        paths["/register"]["post"]["security"] = []
        paths["/register"]["post"]["summary"] = "User registration"
        paths["/register"]["post"]["description"] = "Register a new user with email, username and password."
        paths["/register"]["post"]["tags"] = ["Authentication"]
    if "/login" in paths and "post" in paths["/login"]:
        paths["/login"]["post"]["security"] = []
        paths["/login"]["post"]["summary"] = "User login"
        paths["/login"]["post"]["description"] = "Authenticate a user with email and password."
        paths["/login"]["post"]["tags"] = ["Authentication"]
    if "/set_secret" in paths and "post" in paths["/set_secret"]:
        paths["/set_secret"]["post"]["summary"] = "Set secret"
        paths["/set_secret"]["post"]["description"] = "Save a secret on the server using the username, token, and the secret text."
    if "/get_secret" in paths and "get" in paths["/get_secret"]:
        paths["/get_secret"]["get"]["summary"] = "Get secret"
        paths["/get_secret"]["get"]["description"] = "Retrieve a secret based on the provided username."

    # Tags
    openapi_schema["tags"] = [
        {"name": "Authentication", "description": "Operations related to user authentication"}
    ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

# -----------------------------
# Run Server
# -----------------------------
if __name__ == "__main__":
    # Start the Uvicorn server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)