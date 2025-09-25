import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Security, Query
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from passlib.hash import pbkdf2_sha256
import jwt


APP_SECRET = os.environ.get("APP_SECRET", "change-this-in-production")

DB_PATH = "db.sqlite3"

app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")
bearer_scheme = HTTPBearer(auto_error=False)


def init_db() -> None:
    """
    Initialize the SQLite database and create required tables.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL
            );

            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TIMESTAMP NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    except sqlite3.Error:
        # If database initialization fails, raise a generic error; do not leak details.
        raise RuntimeError("Failed to initialize the database.")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def get_db():
    """
    Dependency that provides a SQLite connection per request, ensuring foreign keys are enabled.
    """
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def hash_password(password: str) -> str:
    """
    Hash the password using a strong KDF (PBKDF2-SHA256).
    """
    return pbkdf2_sha256.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify a password against its hash.
    """
    try:
        return pbkdf2_sha256.verify(password, password_hash)
    except Exception:
        return False


def create_access_token(user_id: int, username: str, email: str, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a signed JWT access token containing user identity claims.
    """
    if not expires_delta:
        expires_delta = timedelta(hours=12)
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "iat": now,
        "exp": now + int(expires_delta.total_seconds()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm="HS256")
    return token


def decode_token(token: str) -> dict:
    """
    Decode a JWT token and return its payload if valid.
    """
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
    db: sqlite3.Connection = Depends(get_db),
):
    """
    Security dependency that validates the Authorization: Bearer token and loads the current user.
    """
    if credentials is None or not credentials.scheme.lower() == "bearer" or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    token = credentials.credentials
    payload = decode_token(token)
    user_id = payload.get("sub")
    username = payload.get("username")
    email = payload.get("email")
    if not user_id or not username or not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    try:
        cur = db.execute("SELECT id, email, username FROM users WHERE id = ?", (int(user_id),))
        user = cur.fetchone()
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    return {"id": user["id"], "email": user["email"], "username": user["username"]}


class RegisterRequest(BaseModel):
    email: EmailStr = Field(
        ...,
        examples=["newuser@example.com"],
        description="User email address",
    )
    username: str = Field(
        ...,
        min_length=3,
        max_length=32,
        pattern=r"^[A-Za-z0-9_]+$",
        examples=["user1"],
        description="Alphanumeric username with underscores allowed",
    )
    password: str = Field(
        ...,
        min_length=8,
        examples=["newUserPassword"],
        description="Password (min length 8)",
    )


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user@example.com"])
    password: str = Field(..., min_length=8, examples=["mySecretPassword"])


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_]+$", examples=["user1"])
    secret: str = Field(..., min_length=1, max_length=4096, examples=["mySecret"])


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    """
    Return consistent JSON error bodies with a 'message' field to match the provided OpenAPI schema.
    """
    message = exc.detail if isinstance(exc.detail, str) else "An error occurred"
    return JSONResponse(status_code=exc.status_code, content={"message": message})


@app.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
    description="Register a new user with email, username and password.",
)
async def register(payload: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    """
    Register a new user. Uses parameterized SQL queries to prevent SQL injection and hashes passwords securely.
    """
    # Basic input sanitation handled by Pydantic; enforce uniqueness without leaking specifics.
    try:
        # Pre-check for duplicate email or username
        cur = db.execute("SELECT 1 FROM users WHERE email = ? OR username = ? LIMIT 1", (payload.email, payload.username))
        exists = cur.fetchone()
        if exists:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")

        password_hash = hash_password(payload.password)
        now = datetime.now(timezone.utc)
        db.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (payload.email, payload.username, password_hash, now),
        )
        db.commit()
        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except sqlite3.Error:
        # Do not disclose DB error details
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")
    except Exception:
        # Catch-all to satisfy CWE-703; return generic message
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")


@app.post(
    "/login",
    status_code=status.HTTP_200_OK,
    tags=["Authentication"],
    description="Authenticate a user with email and password.",
)
async def login(payload: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    """
    Authenticate user and return a JWT token. Passwords are verified using a secure hash comparison.
    """
    try:
        cur = db.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (payload.email,))
        user = cur.fetchone()
        if not user or not verify_password(payload.password, user["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        token = create_access_token(user_id=user["id"], username=user["username"], email=user["email"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")


@app.post(
    "/set_secret",
    status_code=status.HTTP_200_OK,
    description="Save a secret on the server using the username, token, and the secret text.",
)
async def set_secret(
    payload: SetSecretRequest,
    current_user: dict = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    """
    Save or update the user's secret. Authorization requires Bearer token and username must match the token's username.
    """
    try:
        # Authorization check to prevent CWE-863 and CWE-284 issues:
        if payload.username != current_user["username"]:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

        now = datetime.now(timezone.utc)
        db.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret = excluded.secret,
                updated_at = excluded.updated_at
            """,
            (current_user["id"], payload.secret, now),
        )
        db.commit()

        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except sqlite3.Error:
        # Do not disclose details; conservative error handling
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


@app.get(
    "/get_secret",
    status_code=status.HTTP_200_OK,
    description="Retrieve a secret based on the provided username.",
)
async def get_secret(
    username: str = Query(..., examples=["user1"]),
    current_user: dict = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    """
    Retrieve the user's secret. Authorization requires Bearer token and username must match the token's username.
    """
    try:
        # Authorization check to prevent invalid access.
        if username != current_user["username"]:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

        cur = db.execute("SELECT secret FROM secrets WHERE user_id = ?", (current_user["id"],))
        row = cur.fetchone()
        secret_value = row["secret"] if row else ""
        return {"secret": secret_value}
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


def custom_openapi():
    """
    Customize the OpenAPI schema to match the provided specification, including global security and tags.
    """
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Secret Storage",
        version="1.0.0",
        description="A secure cloud storage app for string secrets.",
        routes=app.routes,
    )
    # Security scheme
    components = openapi_schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Global security requirement
    openapi_schema["security"] = [{"bearerAuth": []}]
    # Tags
    openapi_schema["tags"] = [
        {"name": "Authentication", "description": "Operations related to user authentication"}
    ]
    # Override security for endpoints that should be public
    paths = openapi_schema.get("paths", {})
    if "/register" in paths and "post" in paths["/register"]:
        openapi_schema["paths"]["/register"]["post"]["security"] = []
    if "/login" in paths and "post" in paths["/login"]:
        openapi_schema["paths"]["/login"]["post"]["security"] = []
    app.openapi_schema = openapi_schema
    return openapi_schema


app.openapi = custom_openapi


@app.on_event("startup")
def on_startup():
    init_db()


if __name__ == "__main__":
    # Start the app on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)