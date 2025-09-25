import os
import sqlite3
import secrets as std_secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Request, status, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn

# Configuration
DB_PATH = "db.sqlite3"
APP_SECRET = os.environ.get("APP_SECRET") or std_secrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = 60  # Token expiration time


# Initialize FastAPI
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    contact={"name": "Secret Storage"},
)

http_bearer = HTTPBearer(auto_error=False)  # manual error handling for consistent "message" payloads


# Database utilities
def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    # Enforce foreign key constraints
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    try:
        conn = get_connection()
        cur = conn.cursor()
        # Users table
        cur.execute(
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
        # Secrets table: one secret per user
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    except Exception:
        # Do not expose internal details; ensure CWE-703 safe handling
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.on_event("startup")
def on_startup():
    init_db()


# Models
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=1, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    secret: str = Field(min_length=1, max_length=10000)


# Helper functions
def create_jwt_token(user_id: int, email: str, username: str) -> str:
    now = datetime.utcnow()
    payload = {
        "iss": "secret-storage-app",
        "sub": str(user_id),
        "email": email,
        "username": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXP_MINUTES)).timestamp()),
        "jti": std_secrets.token_urlsafe(16),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_jwt_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def find_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    return row


def find_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    return row


def find_user_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[sqlite3.Row]:
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    return row


def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> bool:
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
            (email, username, password_hash),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # Unique constraint violation or invalid data
        return False
    except Exception:
        # Unexpected DB error
        return False


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> bool:
    try:
        cur = conn.cursor()
        # Safe UPSERT to prevent race conditions and SQL injection
        cur.execute(
            """
            INSERT INTO secrets (user_id, secret)
            VALUES (?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret=excluded.secret,
                updated_at=CURRENT_TIMESTAMP
            """,
            (user_id, secret),
        )
        conn.commit()
        return True
    except Exception:
        return False


def get_secret(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.cursor()
    cur.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if row is None:
        return None
    return row["secret"]


# Routes

@app.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
    summary="User registration",
    description="Register a new user with email, username and password.",
)
def register(req: RegisterRequest):
    try:
        conn = get_connection()
        # Validate uniqueness
        existing_email = find_user_by_email(conn, req.email)
        existing_username = find_user_by_username(conn, req.username)
        if existing_email is not None or existing_username is not None:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )
        # Hash password securely (CWE-522 mitigation)
        password_hash = pbkdf2_sha256.hash(req.password)
        created = create_user(conn, req.email, req.username, password_hash)
        if not created:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )
        return {"message": "Registration successful"}
    except Exception:
        # Handle unexpected errors without leaking details (CWE-703)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "Internal server error"},
        )
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.post(
    "/login",
    status_code=status.HTTP_200_OK,
    tags=["Authentication"],
    summary="User login",
    description="Authenticate a user with email and password.",
)
def login(req: LoginRequest):
    try:
        conn = get_connection()
        user = find_user_by_email(conn, req.email)
        if user is None:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
            )
        # Verify password securely
        password_hash = user["password_hash"]
        if not pbkdf2_sha256.verify(req.password, password_hash):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
            )
        token = create_jwt_token(user_id=user["id"], email=user["email"], username=user["username"])
        return {"token": token, "message": "Login successful"}
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "Internal server error"},
        )
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.post(
    "/set_secret",
    status_code=status.HTTP_200_OK,
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(req: SetSecretRequest, credentials: HTTPAuthorizationCredentials = Depends(http_bearer)):
    # Authorization check (CWE-284, CWE-863 mitigation)
    if credentials is None or not credentials.scheme.lower() == "bearer" or not credentials.credentials:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )
    token = credentials.credentials
    payload = decode_jwt_token(token)
    if payload is None:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )
    # Ensure the token corresponds to the same username to prevent privilege escalation
    token_username = payload.get("username")
    token_sub = payload.get("sub")
    if token_username is None or token_sub is None or token_username != req.username:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )
    try:
        conn = get_connection()
        # Verify user existence from token
        user = find_user_by_username(conn, req.username)
        if user is None:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid authentication token"},
            )
        # Store secret securely with parameterized queries (CWE-89 mitigation)
        ok = upsert_secret(conn, user_id=user["id"], secret=req.secret)
        if not ok:
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"message": "Internal server error"},
            )
        return {"message": "Secret has been set successfully"}
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "Internal server error"},
        )
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.get(
    "/get_secret",
    status_code=status.HTTP_200_OK,
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret_endpoint(username: str, credentials: HTTPAuthorizationCredentials = Depends(http_bearer)):
    # Authorization check
    if credentials is None or not credentials.scheme.lower() == "bearer" or not credentials.credentials:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )
    token = credentials.credentials
    payload = decode_jwt_token(token)
    if payload is None:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )
    token_username = payload.get("username")
    token_sub = payload.get("sub")
    if token_username is None or token_sub is None or token_username != username:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )
    try:
        conn = get_connection()
        user = find_user_by_username(conn, username)
        if user is None:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid authentication token"},
            )
        secret_value = get_secret(conn, user_id=user["id"])
        # If no secret set yet, return empty string to satisfy schema shape
        return {"secret": secret_value if secret_value is not None else ""}
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "Internal server error"},
        )
    finally:
        try:
            conn.close()
        except Exception:
            pass


# Customize OpenAPI to align with requested schema (security schemes and global security)
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Secret Storage",
        version="1.0.0",
        description="A secure cloud storage app for string secrets.",
        routes=app.routes,
    )
    # Ensure securitySchemes
    components = openapi_schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Set global security
    openapi_schema["security"] = [{"bearerAuth": []}]
    # Ensure register and login are open (security: [])
    paths = openapi_schema.get("paths", {})
    if "/register" in paths and "post" in paths["/register"]:
        paths["/register"]["post"]["security"] = []
        paths["/register"]["post"]["tags"] = ["Authentication"]
    if "/login" in paths and "post" in paths["/login"]:
        paths["/login"]["post"]["security"] = []
        paths["/login"]["post"]["tags"] = ["Authentication"]
    # Tag description
    openapi_schema["tags"] = [
        {"name": "Authentication", "description": "Operations related to user authentication"},
    ]
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


if __name__ == "__main__":
    # Run the web server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)