import os
import re
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Security, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, Field, EmailStr
from email_validator import validate_email, EmailNotValidError
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn

# ----------------------------
# Configuration and Security
# ----------------------------

APP_TITLE = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

# Application secret for JWT signing
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to random secret if not provided (for development)
    # In production, APP_SECRET must be set.
    import secrets

    APP_SECRET = secrets.token_urlsafe(64)

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 12

# Logger setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secret-storage")

# Security scheme
bearer_scheme = HTTPBearer(auto_error=False)

# ----------------------------
# FastAPI app initialization
# ----------------------------

app = FastAPI(title=APP_TITLE, description=APP_DESCRIPTION, version=APP_VERSION)

# ----------------------------
# Database Helpers
# ----------------------------

DB_PATH = "db.sqlite3"


def get_connection() -> sqlite3.Connection:
    """
    Create a new SQLite connection for each operation to avoid threading issues.
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Enforce foreign keys
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    conn = get_connection()
    try:
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
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    except Exception as e:
        logger.exception("Failed to initialize database: %s", e)
        raise
    finally:
        conn.close()


init_db()

# ----------------------------
# Utility Functions
# ----------------------------


def validate_username(username: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,32}", username))


def hash_password(password: str) -> str:
    # pbkdf2_sha256 is available without external dependencies
    return pbkdf2_sha256.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, password_hash)
    except Exception:
        # Handle corrupted hash or other edge cases securely
        return False


def create_access_token(user_id: int, username: str, email: str) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    payload = {
        "sub": str(user_id),  # subject as string for compatibility
        "username": username,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute(
        "SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,)
    )
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret_text: str):
    # Try update first to avoid relying on UPSERT syntax differences
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
        (secret_text, now, user_id),
    )
    if cur.rowcount == 0:
        conn.execute(
            "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
            (user_id, secret_text, now),
        )
    conn.commit()


def get_secret(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if row:
        return row["secret"]
    return None


# ----------------------------
# Security Dependency
# ----------------------------


async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)):
    if credentials is None or not credentials.scheme.lower() == "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"}
        )
    token = credentials.credentials
    try:
        payload = decode_access_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"}
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"}
        )

    sub = payload.get("sub")
    username = payload.get("username")
    email = payload.get("email")
    if not sub or not username or not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"}
        )

    try:
        user_id = int(sub)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"}
        )

    conn = get_connection()
    try:
        user = get_user_by_id(conn, user_id)
        if user is None or user["username"] != username or user["email"] != email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"}
            )
        return {"id": user["id"], "email": user["email"], "username": user["username"]}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error during authorization: %s", e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"}
        )
    finally:
        conn.close()


# ----------------------------
# Pydantic Models
# ----------------------------


class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., min_length=3, max_length=32, example="user1")
    password: str = Field(..., min_length=8, max_length=128, example="newUserPassword")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: str = Field(..., min_length=8, max_length=128, example="pass1")


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32, example="user1")
    secret: str = Field(..., min_length=1, max_length=4096, example="mySecret")


class MessageResponse(BaseModel):
    message: str


class LoginResponse(BaseModel):
    token: str
    message: str


class SecretResponse(BaseModel):
    secret: str


# ----------------------------
# Routes
# ----------------------------


@app.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    response_model=MessageResponse,
    tags=["Authentication"],
)
async def register(req: RegisterRequest):
    # Validate email explicitly to provide clear error
    try:
        validate_email(req.email, check_deliverability=False)
    except EmailNotValidError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )

    # Validate username format
    if not validate_username(req.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )

    # Hash password
    password_hash = hash_password(req.password)

    conn = get_connection()
    try:
        # Check if email or username already exists
        cur = conn.execute(
            "SELECT id FROM users WHERE email = ? OR username = ?",
            (req.email.strip().lower(), req.username.strip()),
        )
        if cur.fetchone():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )

        created_at = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (req.email.strip().lower(), req.username.strip(), password_hash, created_at),
        )
        conn.commit()
        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Registration failed: %s", e)
        # Avoid leaking internal errors
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    finally:
        conn.close()


@app.post(
    "/login",
    response_model=LoginResponse,
    tags=["Authentication"],
)
async def login(req: LoginRequest):
    # Validate email (normalization)
    try:
        v = validate_email(req.email, check_deliverability=False)
        normalized_email = v.email
    except EmailNotValidError:
        # Normalize error message to avoid revealing specifics
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"},
        )

    conn = get_connection()
    try:
        user = get_user_by_email(conn, normalized_email.lower())
        if not user:
            # Dummy verification to keep timing similar
            verify_password("invalid", hash_password("invalid"))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )

        if not verify_password(req.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )

        token = create_access_token(user_id=int(user["id"]), username=user["username"], email=user["email"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Login failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"},
        )
    finally:
        conn.close()


@app.post(
    "/set_secret",
    response_model=MessageResponse,
)
async def set_secret(req: SetSecretRequest, current_user: dict = Security(get_current_user)):
    # Ensure the username in request matches the authenticated user (prevent horizontal privilege escalation)
    if req.username.strip() != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    conn = get_connection()
    try:
        upsert_secret(conn, user_id=int(current_user["id"]), secret_text=req.secret)
        return {"message": "Secret has been set successfully"}
    except Exception as e:
        logger.exception("Setting secret failed: %s", e)
        # Generic error to avoid leaking info
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )
    finally:
        conn.close()


@app.get(
    "/get_secret",
    response_model=SecretResponse,
)
async def get_secret_endpoint(username: str, current_user: dict = Security(get_current_user)):
    # Authorization: only allow fetching own secret
    if username.strip() != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    conn = get_connection()
    try:
        secret_text = get_secret(conn, user_id=int(current_user["id"]))
        # If no secret set, return empty string to adhere to schema expectations
        return {"secret": secret_text if secret_text is not None else ""}
    except Exception as e:
        logger.exception("Getting secret failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )
    finally:
        conn.close()


# ----------------------------
# Custom OpenAPI to align with provided schema
# ----------------------------

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=APP_TITLE,
        version=APP_VERSION,
        description=APP_DESCRIPTION,
        routes=app.routes,
    )

    # Ensure bearer security scheme exists
    components = openapi_schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }

    # Global security requirement
    openapi_schema["security"] = [{"bearerAuth": []}]

    # Adjust per-path security to match schema (register and login should be public)
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

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

# ----------------------------
# Error Handlers (optional, to satisfy CWE-703)
# ----------------------------


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """
    Add basic security headers. While not strictly required, they help reduce risk.
    """
    try:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response
    except Exception as e:
        logger.exception("Unhandled application error: %s", e)
        # Return a generic 500 without leaking details
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )


# ----------------------------
# Entrypoint
# ----------------------------

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)