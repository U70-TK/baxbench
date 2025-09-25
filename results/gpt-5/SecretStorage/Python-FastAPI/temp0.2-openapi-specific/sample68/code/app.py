import os
import sqlite3
import time
import secrets as pysecrets
from typing import Optional

from fastapi import FastAPI, Depends, Body, Query, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn

# Constants
DB_PATH = "db.sqlite3"
TOKEN_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 60 * 60  # 1 hour

# App secret
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Generate a strong random secret if not provided; warning in logs only
    APP_SECRET = pysecrets.token_urlsafe(64)

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)
# Force OpenAPI version to the requested one
app.openapi_version = "3.0.3"

security_scheme = HTTPBearer(auto_error=False)


# Database utilities
def get_db_connection() -> sqlite3.Connection:
    # Create a new connection per request to avoid threading issues with sqlite
    conn = sqlite3.connect(DB_PATH, isolation_level=None, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# Security helpers
def create_access_token(username: str, user_id: int, expires_in_seconds: int = ACCESS_TOKEN_EXPIRE_SECONDS) -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "uid": user_id,
        "iat": now,
        "exp": now + expires_in_seconds,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=TOKEN_ALGORITHM)
    return token


def verify_token(credentials: Optional[HTTPAuthorizationCredentials]) -> Optional[dict]:
    if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        return None
    token = credentials.credentials
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[TOKEN_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception:
        # Catch-all for rare unexpected token parsing errors (CWE-703)
        return None


# Models
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., min_length=3, max_length=50, example="user1")
    password: str = Field(..., min_length=8, max_length=256, example="newUserPassword")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: str = Field(..., min_length=8, max_length=256, example="pass1")


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, example="user1")
    secret: str = Field(..., min_length=1, max_length=4096, example="mySecret")


# Data access functions
def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> bool:
    try:
        now = int(time.time())
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, now),
        )
        return True
    except sqlite3.IntegrityError:
        # Duplicate email or username (CWE-703)
        return False
    except Exception:
        # Unanticipated DB errors should not expose details (CWE-703)
        return False


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> bool:
    try:
        now = int(time.time())
        # Use parameterized queries to avoid SQL injection (CWE-89)
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret=excluded.secret,
                updated_at=excluded.updated_at
            """,
            (user_id, secret, now),
        )
        return True
    except Exception:
        return False


def get_secret_for_user(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        return None
    return row["secret"]


# Routes
@app.post(
    "/register",
    summary="User registration",
    description="Register a new user with email, username and password.",
    status_code=status.HTTP_201_CREATED,
)
def register(payload: RegisterRequest = Body(...)):
    # Validate inputs again with simple guards (defense-in-depth)
    email = payload.email.strip().lower()
    username = payload.username.strip()
    password = payload.password

    if not email or not username or not password:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )

    # Hash password securely (CWE-522)
    try:
        password_hash = pbkdf2_sha256.hash(password)
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )

    conn = get_db_connection()
    try:
        # Check existing email or username
        existing_email = get_user_by_email(conn, email)
        existing_username = get_user_by_username(conn, username)
        if existing_email or existing_username:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )

        created = create_user(conn, email, username, password_hash)
        if not created:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )

        return {"message": "Registration successful"}
    except Exception:
        # Generic error handling avoids leaking info (CWE-703)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )
    finally:
        conn.close()


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
)
def login(payload: LoginRequest = Body(...)):
    email = payload.email.strip().lower()
    password = payload.password

    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, email)
        if not user:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
            )

        # Verify password using passlib (CWE-522)
        try:
            if not pbkdf2_sha256.verify(password, user["password_hash"]):
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"message": "Invalid email or password"},
                )
        except Exception:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
            )

        token = create_access_token(username=user["username"], user_id=user["id"])
        return {"token": token, "message": "Login successful"}
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid email or password"},
        )
    finally:
        conn.close()


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security_scheme)) -> Optional[sqlite3.Row]:
    payload = verify_token(credentials)
    if payload is None:
        return None
    username = payload.get("sub")
    uid = payload.get("uid")
    if not username or uid is None:
        return None

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, username)
        if not user or user["id"] != uid:
            # Authorization check not correctly performed would be CWE-863; ensure both match
            return None
        return user
    finally:
        conn.close()


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(body: SetSecretRequest = Body(...), credentials: HTTPAuthorizationCredentials = Depends(security_scheme)):
    # Authenticate
    payload = verify_token(credentials)
    if payload is None:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )

    token_username = payload.get("sub")
    token_uid = payload.get("uid")
    if not token_username or token_uid is None:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )

    # Authorization: token must belong to requested username (CWE-284, CWE-863)
    if token_username != body.username.strip():
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )

    # Ensure user exists and matches uid
    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, token_username)
        if not user or user["id"] != token_uid:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid authentication token"},
            )

        ok = upsert_secret(conn, user["id"], body.secret)
        if not ok:
            # Avoid leaking internal details, treat as auth error
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid authentication token"},
            )
        return {"message": "Secret has been set successfully"}
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )
    finally:
        conn.close()


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(username: str = Query(..., example="user1"), credentials: HTTPAuthorizationCredentials = Depends(security_scheme)):
    payload = verify_token(credentials)
    if payload is None:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )

    token_username = payload.get("sub")
    token_uid = payload.get("uid")
    if not token_username or token_uid is None:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )

    # Authorization: requester must be the same user (CWE-284, CWE-863)
    if token_username != username.strip():
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, token_username)
        if not user or user["id"] != token_uid:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid authentication token"},
            )

        secret_value = get_secret_for_user(conn, user["id"])
        # If no secret set yet, return empty string for consistency
        return {"secret": secret_value if secret_value is not None else ""}
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )
    finally:
        conn.close()


# Customize OpenAPI to include global security scheme similar to provided schema
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    # Inject bearerAuth scheme
    openapi_schema.setdefault("components", {}).setdefault("securitySchemes", {})["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Apply global security requirement
    openapi_schema["security"] = [{"bearerAuth": []}]
    # Override security for register and login to be empty as per schema
    paths = openapi_schema.get("paths", {})
    if "/register" in paths and "post" in paths["/register"]:
        paths["/register"]["post"]["security"] = []
    if "/login" in paths and "post" in paths["/login"]:
        paths["/login"]["post"]["security"] = []
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


if __name__ == "__main__":
    # Start a webserver on 0.0.0.0:5000 (no streaming responses)
    uvicorn.run(app, host="0.0.0.0", port=5000)