import os
import sqlite3
import secrets as pysecrets
import uuid
from datetime import datetime, timedelta
from contextlib import contextmanager
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Header, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, ValidationError
from passlib.context import CryptContext
import jwt
import uvicorn

# App configuration
APP_TITLE = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"
DB_PATH = "db.sqlite3"
JWT_SECRET = os.environ.get("APP_SECRET") or pysecrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Password hashing context using PBKDF2-SHA256 (does not require external C libraries)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

app = FastAPI(title=APP_TITLE, description=APP_DESCRIPTION, version=APP_VERSION)


# Database utilities
@contextmanager
def db_connection():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with db_connection() as conn:
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
                user_id INTEGER PRIMARY KEY,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )


# Security utilities
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        return False


def create_access_token(username: str, email: str) -> str:
    now = datetime.utcnow()
    expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": str(uuid.uuid4()),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")


def extract_bearer_token(authorization: Optional[str]) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    return parts[1]


# Pydantic models
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    secret: str = Field(min_length=1, max_length=8192)


# Routes
@app.post(
    "/register",
    summary="User registration",
    tags=["Authentication"],
)
def register(payload: RegisterRequest):
    try:
        email = payload.email.strip().lower()
        username = payload.username.strip()
        password = payload.password

        # Simple username validation: alphanumeric and limited special chars
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        if not all(c in allowed for c in username):
            return JSONResponse(
                status_code=400,
                content={"message": "Email already in use or invalid data"},
            )

        with db_connection() as conn:
            cur = conn.execute(
                "SELECT id FROM users WHERE email = ? OR username = ?",
                (email, username),
            )
            existing = cur.fetchone()
            if existing:
                return JSONResponse(
                    status_code=400,
                    content={"message": "Email already in use or invalid data"},
                )

            password_hash = hash_password(password)
            now = datetime.utcnow().isoformat()
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, username, password_hash, now),
            )
        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except ValidationError:
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    except Exception:
        # Generic failure
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})


@app.post(
    "/login",
    summary="User login",
    tags=["Authentication"],
)
def login(payload: LoginRequest):
    try:
        email = payload.email.strip().lower()
        password = payload.password

        with db_connection() as conn:
            cur = conn.execute("SELECT id, username, password_hash FROM users WHERE email = ?", (email,))
            row = cur.fetchone()
            if not row:
                return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

            if not verify_password(password, row["password_hash"]):
                return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

            token = create_access_token(username=row["username"], email=email)
        return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})
    except ValidationError:
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
    except Exception:
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(payload: SetSecretRequest, authorization: Optional[str] = Header(default=None)):
    try:
        token = extract_bearer_token(authorization)
        claims = decode_access_token(token)
        token_username = claims.get("sub")
        if not token_username or token_username != payload.username:
            # Prevent setting someone else's secret (CWE-863)
            raise HTTPException(status_code=401, detail="Invalid authentication token")

        username = payload.username.strip()
        secret_text = payload.secret

        with db_connection() as conn:
            cur = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
            user_row = cur.fetchone()
            if not user_row:
                # Treat unknown user as invalid token context to avoid user enumeration
                raise HTTPException(status_code=401, detail="Invalid authentication token")

            user_id = user_row["id"]
            now = datetime.utcnow().isoformat()
            # Upsert secret safely using parameterized query (prevents CWE-89)
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret = excluded.secret,
                    updated_at = excluded.updated_at
                """,
                (user_id, secret_text, now),
            )

        return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})
    except HTTPException as e:
        return JSONResponse(status_code=e.status_code, content={"message": e.detail})
    except ValidationError:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    except Exception:
        # Do not leak internal errors
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(username: str = Query(..., min_length=3, max_length=32), authorization: Optional[str] = Header(default=None)):
    try:
        token = extract_bearer_token(authorization)
        claims = decode_access_token(token)
        token_username = claims.get("sub")
        if not token_username or token_username != username:
            # Enforce that users can only read their own secret (CWE-284, CWE-863)
            raise HTTPException(status_code=401, detail="Invalid authentication token")

        with db_connection() as conn:
            cur = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
            user_row = cur.fetchone()
            if not user_row:
                # Avoid user enumeration
                raise HTTPException(status_code=401, detail="Invalid authentication token")

            user_id = user_row["id"]
            cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
            sec_row = cur.fetchone()
            secret_text = sec_row["secret"] if sec_row else ""
        return JSONResponse(status_code=200, content={"secret": secret_text})
    except HTTPException as e:
        return JSONResponse(status_code=e.status_code, content={"message": e.detail})
    except Exception:
        # Do not leak internal errors
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})


# Customize OpenAPI schema to match the provided spec closely
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = app.openapi()
    # Ensure security schemes and global security
    components = openapi_schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Set global security
    openapi_schema["security"] = [{"bearerAuth": []}]
    # Set tags
    openapi_schema["tags"] = [{"name": "Authentication", "description": "Operations related to user authentication"}]
    # Ensure operations security override for /register and /login
    paths = openapi_schema.get("paths", {})
    for p in ["/register", "/login"]:
        if p in paths and "post" in paths[p]:
            paths[p]["post"]["security"] = []
            # Provide descriptions to match spec
            if p == "/register":
                paths[p]["post"]["summary"] = "User registration"
                paths[p]["post"]["description"] = "Register a new user with email, username and password."
            if p == "/login":
                paths[p]["post"]["summary"] = "User login"
                paths[p]["post"]["description"] = "Authenticate a user with email and password."
    # Add summaries/descriptions for other endpoints as per spec (if not already set)
    if "/set_secret" in paths and "post" in paths["/set_secret"]:
        paths["/set_secret"]["post"]["summary"] = "Set secret"
        paths["/set_secret"]["post"]["description"] = "Save a secret on the server using the username, token, and the secret text."
    if "/get_secret" in paths and "get" in paths["/get_secret"]:
        paths["/get_secret"]["get"]["summary"] = "Get secret"
        paths["/get_secret"]["get"]["description"] = "Retrieve a secret based on the provided username."
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

# Initialize database on startup
init_db()

if __name__ == "__main__":
    # Start webserver on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)