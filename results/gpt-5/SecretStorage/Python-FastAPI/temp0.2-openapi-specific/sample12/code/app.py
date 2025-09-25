import os
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, Security, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, Field, EmailStr
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn

# ---------------------------
# Configuration and Logging
# ---------------------------

APP_NAME = "Secret Storage"
APP_VERSION = "1.0.0"

logger = logging.getLogger(APP_NAME)
logging.basicConfig(level=logging.INFO)

JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 60

APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Fallback for development; in production, APP_SECRET must be set.
    # Using a random secret will invalidate tokens on each restart.
    import secrets as _secrets

    APP_SECRET = _secrets.token_urlsafe(64)
    logger.warning("APP_SECRET not set. Using a random ephemeral secret. Set APP_SECRET env var for persistence and security.")

DATABASE_PATH = "db.sqlite3"

# ---------------------------
# Database Utilities
# ---------------------------

def get_connection() -> sqlite3.Connection:
    # Create a new connection per request to avoid thread issues
    conn = sqlite3.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    # Ensure foreign keys are enforced
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db() -> None:
    conn = get_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}")
        raise
    finally:
        conn.close()

def fetch_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?;", (email,))
        return cur.fetchone()
    except sqlite3.Error as e:
        logger.error(f"DB error fetching user by email: {e}")
        raise

def fetch_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?;", (username,))
        return cur.fetchone()
    except sqlite3.Error as e:
        logger.error(f"DB error fetching user by username: {e}")
        raise

def upsert_secret(conn: sqlite3.Connection, user_id: int, secret_text: str) -> None:
    try:
        now = datetime.now(timezone.utc)
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET secret = excluded.secret, updated_at = excluded.updated_at;
            """,
            (user_id, secret_text, now),
        )
        conn.commit()
    except sqlite3.Error as e:
        logger.error(f"DB error upserting secret: {e}")
        raise

def get_secret_for_user(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        if row:
            return row["secret"]
        return None
    except sqlite3.Error as e:
        logger.error(f"DB error fetching secret: {e}")
        raise

# ---------------------------
# Security Utilities
# ---------------------------

bearer_scheme = HTTPBearer(auto_error=False)

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    to_encode.update({"iat": int(now.timestamp()), "nbf": int(now.timestamp())})
    expire = now + (expires_delta if expires_delta else timedelta(minutes=TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": int(expire.timestamp())})
    token = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme)) -> Dict[str, Any]:
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    payload = decode_access_token(token)
    subject_username = payload.get("sub")
    if not subject_username or not isinstance(subject_username, str):
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    conn = get_connection()
    try:
        user = fetch_user_by_username(conn, subject_username)
        if not user:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        return {"id": user["id"], "email": user["email"], "username": user["username"]}
    finally:
        conn.close()

# ---------------------------
# Pydantic Models
# ---------------------------

class RegisterRequest(BaseModel):
    email: EmailStr = Field(example="newuser@example.com")
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]{3,64}$", example="user1")
    password: str = Field(min_length=8, max_length=1024, example="newUserPassword")

class RegisterResponse(BaseModel):
    message: str = Field(example="Registration successful")

class ErrorMessage(BaseModel):
    message: str

class LoginRequest(BaseModel):
    email: EmailStr = Field(example="user1@example.com")
    password: str = Field(min_length=8, max_length=1024, example="pass1")

class LoginResponse(BaseModel):
    token: str = Field(example="jwt-token-abc123")
    message: str = Field(example="Login successful")

class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]{3,64}$", example="user1")
    secret: str = Field(min_length=1, max_length=8192, example="mySecret")

class SetSecretResponse(BaseModel):
    message: str = Field(example="Secret has been set successfully")

class GetSecretResponse(BaseModel):
    secret: str = Field(example="The secret associated with the provided details")

# ---------------------------
# FastAPI App
# ---------------------------

app = FastAPI(
    title=APP_NAME,
    description="A secure cloud storage app for string secrets.",
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

@app.on_event("startup")
def on_startup():
    init_db()
    logger.info(f"{APP_NAME} initialized.")

# ---------------------------
# Routes
# ---------------------------

@app.post(
    "/register",
    response_model=RegisterResponse,
    status_code=201,
    tags=["Authentication"],
    responses={
        201: {"description": "Successful registration", "model": RegisterResponse},
        400: {"description": "Bad Request", "model": ErrorMessage},
    },
)
def register(req: RegisterRequest):
    email_norm = req.email.lower().strip()
    username_norm = req.username.strip()

    # Basic validation already handled by Pydantic; perform any extra checks here
    conn = get_connection()
    try:
        # Check existing user by email or username
        existing_email = fetch_user_by_email(conn, email_norm)
        existing_username = fetch_user_by_username(conn, username_norm)
        if existing_email or existing_username:
            raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
        # Hash the password securely using PBKDF2
        password_hash = pbkdf2_sha256.hash(req.password)

        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?);",
            (email_norm, username_norm, password_hash, datetime.now(timezone.utc), datetime.now(timezone.utc)),
        )
        conn.commit()
        return {"message": "Registration successful"}
    except sqlite3.Error:
        # Do not leak internal errors to clients
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
    finally:
        conn.close()

@app.post(
    "/login",
    response_model=LoginResponse,
    tags=["Authentication"],
    responses={
        200: {"description": "Successful login", "model": LoginResponse},
        401: {"description": "Unauthorized", "model": ErrorMessage},
    },
)
def login(req: LoginRequest):
    email_norm = req.email.lower().strip()
    conn = get_connection()
    try:
        user = fetch_user_by_email(conn, email_norm)
        if not user or not pbkdf2_sha256.verify(req.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
        token_payload = {
            "sub": user["username"],
            "iss": APP_NAME,
            "jti": os.urandom(16).hex(),
        }
        token = create_access_token(token_payload, timedelta(minutes=TOKEN_EXPIRE_MINUTES))
        return {"token": token, "message": "Login successful"}
    except sqlite3.Error:
        # In case of DB issues, avoid leaking info; treat as auth failure
        raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
    finally:
        conn.close()

@app.post(
    "/set_secret",
    response_model=SetSecretResponse,
    responses={
        200: {"description": "Secret set successfully", "model": SetSecretResponse},
        401: {"description": "Unauthorized", "model": ErrorMessage},
    },
)
def set_secret(req: SetSecretRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    # Authorization: ensure the token subject matches the provided username
    if req.username != current_user["username"]:
        # Incorrect or mismatched authorization (CWE-863)
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    conn = get_connection()
    try:
        upsert_secret(conn, current_user["id"], req.secret)
        return {"message": "Secret has been set successfully"}
    except sqlite3.Error:
        # Handle unexpected DB errors gracefully (CWE-703)
        raise HTTPException(status_code=500, detail={"message": "An unexpected error occurred"})
    finally:
        conn.close()

@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
    responses={
        200: {"description": "Secret retrieved successfully", "model": GetSecretResponse},
        401: {"description": "Unauthorized", "model": ErrorMessage},
    },
)
def get_secret(username: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    # Authorization: ensure token subject matches the requested username
    if username != current_user["username"]:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    conn = get_connection()
    try:
        secret_text = get_secret_for_user(conn, current_user["id"])
        # The schema specifies a 200 response; if no secret, return empty string
        return {"secret": secret_text if secret_text is not None else ""}
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail={"message": "An unexpected error occurred"})
    finally:
        conn.close()

# ---------------------------
# OpenAPI Customization
# ---------------------------

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=APP_NAME,
        version=APP_VERSION,
        description="A secure cloud storage app for string secrets.",
        routes=app.routes,
    )
    # Security schemes
    openapi_schema.setdefault("components", {}).setdefault("securitySchemes", {})
    openapi_schema["components"]["securitySchemes"]["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Global security requirement
    openapi_schema["security"] = [{"bearerAuth": []}]
    # Tags as per spec
    openapi_schema["tags"] = [
        {"name": "Authentication", "description": "Operations related to user authentication"}
    ]
    # Override /register and /login to have no security
    paths = openapi_schema.get("paths", {})
    if "/register" in paths and "post" in paths["/register"]:
        paths["/register"]["post"]["security"] = []
    if "/login" in paths and "post" in paths["/login"]:
        paths["/login"]["post"]["security"] = []
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# ---------------------------
# Uvicorn Entrypoint
# ---------------------------

if __name__ == "__main__":
    # Run the webserver on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)