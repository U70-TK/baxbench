import os
import re
import sqlite3
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, status, Depends, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from passlib.hash import pbkdf2_sha256
import jwt
from jwt import InvalidTokenError, ExpiredSignatureError
from email_validator import validate_email, EmailNotValidError
import uvicorn


DB_PATH = "db.sqlite3"
# Use provided APP_SECRET or generate a strong ephemeral secret for runtime.
# In production, always set APP_SECRET in environment.
SECRET_KEY = os.environ.get("APP_SECRET") or secrets.token_urlsafe(64)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

bearer_scheme = HTTPBearer(auto_error=False)


# ---------------------------
# Database utilities
# ---------------------------
def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    # Return rows as dict-like objects
    conn.row_factory = sqlite3.Row
    # Enforce foreign keys
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    try:
        conn = get_db_connection()
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
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    except Exception:
        # If DB init fails, raise a clean error to avoid leaking details
        raise RuntimeError("Failed to initialize database.")
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.on_event("startup")
def on_startup():
    init_db()


# ---------------------------
# Security utilities
# ---------------------------
def create_access_token(*, user_id: int, username: str, email: str, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "email": email.lower(),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token


def validate_username(username: str) -> bool:
    # Allow alphanumerics, underscore and hyphen, length 3-50
    return bool(re.fullmatch(r"[A-Za-z0-9_\-]{3,50}", username))


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"require": ["exp", "sub", "username", "email"]})
        sub = payload.get("sub")
        username = payload.get("username")
        email = payload.get("email")
        if sub is None or username is None or email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        try:
            user_id = int(sub)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        conn = get_db_connection()
        try:
            row = conn.execute("SELECT id, email, username FROM users WHERE id = ?;", (user_id,)).fetchone()
            if not row:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={"message": "Invalid authentication token"},
                )
            # Ensure token claims still match DB state (prevents outdated token use if user data changes)
            if row["email"].lower() != str(email).lower() or row["username"] != str(username):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={"message": "Invalid authentication token"},
                )
            return {"id": row["id"], "email": row["email"], "username": row["username"]}
        finally:
            conn.close()
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    except HTTPException:
        # Propagate already formed HTTPException
        raise
    except Exception:
        # Any other unexpected error should be treated as unauthorized to avoid detail leakage
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )


# ---------------------------
# Request Models
# ---------------------------
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., min_length=3, max_length=50, example="user1")
    password: str = Field(..., min_length=8, example="newUserPassword")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: str = Field(..., min_length=8, example="pass1")


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, example="user1")
    secret: str = Field(..., example="mySecret")


# ---------------------------
# Endpoints
# ---------------------------
@app.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    responses={
        201: {"description": "Successful registration", "content": {"application/json": {"schema": {"type": "object", "properties": {"message": {"type": "string"}}}}}},
        400: {"description": "Bad Request", "content": {"application/json": {"schema": {"type": "object", "properties": {"message": {"type": "string"}}}}}},
    },
)
def register(req: RegisterRequest):
    # Normalize input
    email = req.email.lower().strip()
    username = req.username.strip()
    password = req.password

    # Validate email using email_validator explicitly (pydantic already does basic checks)
    try:
        validate_email(email, check_deliverability=False)
    except EmailNotValidError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )

    # Validate username format
    if not validate_username(username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )

    # Enforce password policy
    if len(password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )

    # Hash password securely (CWE-522 mitigation)
    password_hash = pbkdf2_sha256.hash(password)

    # Persist user
    conn = get_db_connection()
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (email, username, password_hash, now_iso),
        )
        conn.commit()
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Unique constraint violation (email or username exists) -> generic message to avoid enumeration
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    except Exception:
        # Unexpected DB error
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    finally:
        conn.close()


@app.post(
    "/login",
    responses={
        200: {"description": "Successful login", "content": {"application/json": {"schema": {"type": "object", "properties": {"token": {"type": "string"}, "message": {"type": "string"}}}}}},
        401: {"description": "Unauthorized", "content": {"application/json": {"schema": {"type": "object", "properties": {"message": {"type": "string"}}}}}},
    },
)
def login(req: LoginRequest):
    email = req.email.lower().strip()
    password = req.password

    conn = get_db_connection()
    try:
        row = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?;", (email,)).fetchone()
        if not row or not pbkdf2_sha256.verify(password, row["password_hash"]):
            # Uniform message to avoid credential enumeration
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )
        token = create_access_token(user_id=row["id"], username=row["username"], email=row["email"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"},
        )
    finally:
        conn.close()


@app.post(
    "/set_secret",
    responses={
        200: {"description": "Secret set successfully", "content": {"application/json": {"schema": {"type": "object", "properties": {"message": {"type": "string"}}}}}},
        401: {"description": "Unauthorized", "content": {"application/json": {"schema": {"type": "object", "properties": {"message": {"type": "string"}}}}}},
    },
)
def set_secret(req: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    # Authorization check (CWE-284, CWE-863 mitigation)
    if not validate_username(req.username) or req.username != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    secret_text = req.secret
    # Basic guard against excessive size
    if not isinstance(secret_text, str) or len(secret_text) > 10000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Invalid secret payload"},
        )

    conn = get_db_connection()
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        # Upsert secret with parameterized queries (CWE-89 mitigation)
        existing = conn.execute("SELECT user_id FROM secrets WHERE user_id = ?;", (current_user["id"],)).fetchone()
        if existing:
            conn.execute("UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?;", (secret_text, now_iso, current_user["id"]))
        else:
            conn.execute("INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?);", (current_user["id"], secret_text, now_iso))
        conn.commit()
        return {"message": "Secret has been set successfully"}
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    finally:
        conn.close()


@app.get(
    "/get_secret",
    responses={
        200: {"description": "Secret retrieved successfully", "content": {"application/json": {"schema": {"type": "object", "properties": {"secret": {"type": "string"}}}}}},
        401: {"description": "Unauthorized", "content": {"application/json": {"schema": {"type": "object", "properties": {"message": {"type": "string"}}}}}},
    },
)
def get_secret(username: str = Query(..., min_length=3, max_length=50, example="user1"), current_user: dict = Depends(get_current_user)):
    # Authorization check: prevent reading other users' secrets (CWE-284, CWE-863 mitigation)
    if not validate_username(username) or username != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    conn = get_db_connection()
    try:
        row = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (current_user["id"],)).fetchone()
        secret_text = row["secret"] if row else ""
        return {"secret": secret_text}
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    finally:
        conn.close()


# ---------------------------
# Custom OpenAPI security scheme (metadata)
# ---------------------------
# Annotate the OpenAPI components/securitySchemes to match the provided schema
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = app.openapi()
    # Inject bearerAuth security scheme if not present
    components = openapi_schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Global security requirement
    openapi_schema["security"] = [{"bearerAuth": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


if __name__ == "__main__":
    # Start server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)