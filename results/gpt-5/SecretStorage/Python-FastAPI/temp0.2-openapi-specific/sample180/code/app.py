import os
import sqlite3
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta
from typing import Optional, Tuple

import jwt  # PyJWT
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, EmailStr, Field, ValidationError

# Constants for password hashing
PWD_HASH_NAME = "sha256"
PWD_ITERATIONS = 310000
DB_PATH = "db.sqlite3"

# Application secret for JWT
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate a strong ephemeral secret if none is provided.
    # This means tokens will not be valid across restarts.
    APP_SECRET = secrets.token_urlsafe(64)
    print("WARNING: APP_SECRET not set. Generated an ephemeral secret. "
          "For production, set APP_SECRET in environment.")

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# ---------- Database Utilities ----------

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    # Enforce foreign key constraints
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        # Optional indexes (uniques already enforce, but add if needed)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
    except sqlite3.Error:
        # If DB can't initialize, raise an exception to stop app
        conn.close()
        raise
    finally:
        conn.close()

@app.on_event("startup")
def on_startup():
    init_db()

# ---------- Security and JWT Utilities ----------

def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    if salt is None:
        salt = secrets.token_bytes(16)
    # pbkdf2_hmac returns bytes
    pwd_hash = hashlib.pbkdf2_hmac(PWD_HASH_NAME, password.encode("utf-8"), salt, PWD_ITERATIONS)
    return salt, pwd_hash

def verify_password(password: str, salt: bytes, expected_hash: bytes) -> bool:
    pwd_hash = hashlib.pbkdf2_hmac(PWD_HASH_NAME, password.encode("utf-8"), salt, PWD_ITERATIONS)
    return hmac.compare_digest(pwd_hash, expected_hash)

def create_jwt_token(user_id: int, username: str, email: str, expires_in_seconds: int = 3600) -> str:
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "iat": now,
        "nbf": now,
        "exp": now + expires_in_seconds,
        "jti": secrets.token_urlsafe(8),
        "scope": "user",
    }
    token = jwt.encode(payload, APP_SECRET, algorithm="HS256")
    return token

def _parse_bearer_token_from_request(request: Request) -> str:
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    return parts[1]

def get_user_from_token(request: Request) -> sqlite3.Row:
    """
    Validates the JWT token from the Authorization header and returns the user row.
    Enforces that the token is valid and the user exists.
    """
    token = _parse_bearer_token_from_request(request)
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    user_id = payload.get("sub")
    username = payload.get("username")
    email = payload.get("email")
    if not user_id or not username or not email:
        # Malformed token
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT id, email, username FROM users WHERE id = ? AND username = ? AND email = ?",
            (int(user_id), username, email)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        return row
    except sqlite3.Error:
        # Database issue should not reveal details
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    finally:
        conn.close()

# ---------- Pydantic Models ----------

class RegisterBody(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)

class LoginBody(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

class SetSecretBody(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    secret: str = Field(min_length=1, max_length=4096)

# ---------- Exception Handlers (CWE-703: Robust handling) ----------

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    detail = exc.detail
    if isinstance(detail, dict):
        content = detail
    else:
        content = {"message": str(detail)}
    # Use JSONResponse to ensure application/json content type
    return JSONResponse(status_code=exc.status_code, content=content)

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Avoid leaking internal details
    return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"message": "Internal server error"})

# ---------- Routes ----------

@app.post("/register", status_code=201, tags=["Authentication"])
async def register(body: RegisterBody):
    # Validate and insert new user with secure password hashing.
    conn = get_db_connection()
    try:
        # Check if email or username already exists
        existing_email = conn.execute("SELECT 1 FROM users WHERE email = ?", (str(body.email),)).fetchone()
        existing_username = conn.execute("SELECT 1 FROM users WHERE username = ?", (body.username,)).fetchone()
        if existing_email or existing_username:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )

        salt, pwd_hash = hash_password(body.password)

        conn.execute(
            "INSERT INTO users (email, username, password_salt, password_hash, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            (str(body.email), body.username, salt, pwd_hash)
        )
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Unique constraint violation or other integrity issues
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )
    except sqlite3.Error:
        # Database error: internal server error without leaking details
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    finally:
        conn.close()

@app.post("/login", tags=["Authentication"])
async def login(body: LoginBody):
    conn = get_db_connection()
    try:
        user = conn.execute(
            "SELECT id, email, username, password_salt, password_hash FROM users WHERE email = ?",
            (str(body.email),)
        ).fetchone()
        if not user:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
            )

        salt = user["password_salt"]
        pwd_hash = user["password_hash"]

        if not verify_password(body.password, salt, pwd_hash):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
            )

        token = create_jwt_token(user["id"], user["username"], user["email"])
        return {"token": token, "message": "Login successful"}
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    finally:
        conn.close()

@app.post("/set_secret")
async def set_secret(request: Request, body: SetSecretBody):
    # Authentication and authorization: token must be valid and belong to the same username provided
    auth_user = get_user_from_token(request)
    if auth_user["username"] != body.username:
        # Prevent CWE-863 by strictly checking authorization
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        # Ensure user exists and get id
        user = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (body.username,)
        ).fetchone()
        if not user or user["id"] != auth_user["id"]:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

        # Upsert secret for the user
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, created_at, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET
                secret = excluded.secret,
                updated_at = CURRENT_TIMESTAMP
            """,
            (user["id"], body.secret)
        )
        return {"message": "Secret has been set successfully"}
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    finally:
        conn.close()

@app.get("/get_secret")
async def get_secret(request: Request, username: str):
    # Authentication and authorization: token must be valid and belong to the same username requested
    auth_user = get_user_from_token(request)
    if auth_user["username"] != username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        # Confirm the user exists and matches token
        user = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        if not user or user["id"] != auth_user["id"]:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

        secret_row = conn.execute(
            "SELECT secret FROM secrets WHERE user_id = ?",
            (user["id"],)
        ).fetchone()
        secret_value = secret_row["secret"] if secret_row else ""
        return {"secret": secret_value}
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    finally:
        conn.close()

# ---------- OpenAPI customization to match given schema ----------

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    # Add bearer auth security scheme
    components = openapi_schema.get("components", {})
    components["securitySchemes"] = {
        "bearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }
    openapi_schema["components"] = components
    # Set global security requirement
    openapi_schema["security"] = [{"bearerAuth": []}]
    # Ensure /register and /login are open (override security)
    paths = openapi_schema.get("paths", {})
    for path in ["/register", "/login"]:
        if path in paths:
            for method_key, method_obj in paths[path].items():
                if isinstance(method_obj, dict):
                    method_obj["security"] = []
    # Add tags info
    openapi_schema["tags"] = [
        {"name": "Authentication", "description": "Operations related to user authentication"}
    ]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# ---------- Run server ----------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)