import os
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Security, status, Query
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
import jwt
import uvicorn

# ------------------------------------------------------------------------------
# Configuration and Security
# ------------------------------------------------------------------------------

APP_SECRET = os.environ.get("APP_SECRET") or os.urandom(32).hex()
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DB_PATH = "db.sqlite3"

pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto",
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secret-storage")

# HTTP Bearer security scheme for OpenAPI
bearer_scheme = HTTPBearer(bearerFormat="JWT", scheme_name="bearerAuth")


# ------------------------------------------------------------------------------
# Database Utilities
# ------------------------------------------------------------------------------

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
    except Exception as e:
        logger.error(f"Failed to set PRAGMA foreign_keys: {e}")
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
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
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
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        logger.info("Database initialized.")
    except Exception as e:
        logger.exception(f"Database initialization failed: {e}")
        raise
    finally:
        conn.close()


def create_user(email: str, username: str, password_hash: str) -> int:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?);",
            (email, username, password_hash),
        )
        user_id = cur.lastrowid
        return user_id
    finally:
        conn.close()


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?;", (email,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?;", (username,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?;", (user_id,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def upsert_secret(user_id: int, secret: str) -> None:
    conn = get_connection()
    try:
        cur = conn.cursor()
        # SQLite UPSERT using ON CONFLICT on unique user_id
        cur.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET
                secret = excluded.secret,
                updated_at = CURRENT_TIMESTAMP;
            """,
            (user_id, secret),
        )
    finally:
        conn.close()


def get_secret_by_user_id(user_id: int) -> Optional[str]:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        return row["secret"] if row else None
    finally:
        conn.close()


# ------------------------------------------------------------------------------
# Models
# ------------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=256)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=256)


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    secret: str = Field(min_length=1, max_length=4096)


# ------------------------------------------------------------------------------
# Token Utilities
# ------------------------------------------------------------------------------

def create_access_token(user_id: int, username: str) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
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


def get_current_user(credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)) -> sqlite3.Row:
    token = credentials.credentials
    payload = decode_token(token)
    sub = payload.get("sub")
    username = payload.get("username")
    if sub is None or username is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    try:
        user_id = int(sub)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    user_row = get_user_by_id(user_id)
    if not user_row or user_row["username"] != username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    return user_row


# ------------------------------------------------------------------------------
# FastAPI App and Exception Handling
# ------------------------------------------------------------------------------

app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")


@app.on_event("startup")
def on_startup():
    init_db()


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    # Convert default 422 to 400 to better align with provided OpenAPI schema
    return JSONResponse(status_code=400, content={"message": "Invalid request data"})


# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@app.post("/register", status_code=201, tags=["Authentication"])
def register(payload: RegisterRequest):
    try:
        email = payload.email.lower().strip()
        username = payload.username.strip()
        password_hash = pwd_context.hash(payload.password)

        # Prevent duplicate emails or usernames
        if get_user_by_email(email) is not None or get_user_by_username(username) is not None:
            raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

        create_user(email=email, username=username, password_hash=password_hash)
        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error during registration: {e}")
        # Do not leak internal errors; respond with generic bad request
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})


@app.post("/login", tags=["Authentication"])
def login(payload: LoginRequest):
    try:
        email = payload.email.lower().strip()
        user_row = get_user_by_email(email)
        if not user_row:
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})

        password_hash = user_row["password_hash"]
        if not pwd_context.verify(payload.password, password_hash):
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})

        token = create_access_token(user_id=int(user_row["id"]), username=user_row["username"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error during login: {e}")
        raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})


@app.post("/set_secret")
def set_secret(body: SetSecretRequest, current_user: sqlite3.Row = Depends(get_current_user)):
    try:
        # Authorization: ensure the token user matches the requested username
        if current_user["username"] != body.username.strip():
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

        upsert_secret(user_id=int(current_user["id"]), secret=body.secret)
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error during set_secret: {e}")
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})


@app.get("/get_secret")
def get_secret(username: str = Query(...), current_user: sqlite3.Row = Depends(get_current_user)):
    try:
        # Authorization: ensure the token user matches the requested username
        if current_user["username"] != username.strip():
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

        secret = get_secret_by_user_id(int(current_user["id"]))
        # If no secret found, return empty string to keep schema simple
        return {"secret": secret if secret is not None else ""}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error during get_secret: {e}")
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})


# ------------------------------------------------------------------------------
# OpenAPI Customization to match provided schema more closely
# ------------------------------------------------------------------------------

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    # Ensure the security scheme is named 'bearerAuth'
    components = openapi_schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Set global security requirement
    openapi_schema["security"] = [{"bearerAuth": []}]

    # Disable security for register and login
    paths = openapi_schema.get("paths", {})
    for p in ("/register", "/login"):
        if p in paths and "post" in paths[p]:
            paths[p]["post"]["security"] = []

    # Add tags section
    openapi_schema["tags"] = [
        {"name": "Authentication", "description": "Operations related to user authentication"}
    ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# ------------------------------------------------------------------------------
# Main entry point
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)