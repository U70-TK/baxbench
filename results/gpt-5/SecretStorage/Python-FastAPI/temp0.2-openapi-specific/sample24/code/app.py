import os
import sqlite3
import secrets as seclib
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Security, status, Request, Response, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from passlib.hash import pbkdf2_sha256
import jwt  # PyJWT
from email_validator import validate_email, EmailNotValidError

DB_PATH = "db.sqlite3"

# Load application secret for JWT signing
APP_SECRET = os.environ.get("APP_SECRET") or seclib.token_urlsafe(64)
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Configure HTTP Bearer auth
bearer_scheme = HTTPBearer(auto_error=True)

# --------------------------
# Database utilities
# --------------------------
def _connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30.0, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Apply secure and safe pragmas
    with conn:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
    return conn

def get_db():
    conn = _connect_db()
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass

def init_db():
    conn = _connect_db()
    try:
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
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    user_id INTEGER PRIMARY KEY,
                    secret TEXT,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
    finally:
        try:
            conn.close()
        except Exception:
            pass

@app.on_event("startup")
def _on_startup():
    init_db()

# --------------------------
# Models
# --------------------------
class RegisterRequest(BaseModel):
    email: str = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., min_length=1, max_length=64, examples=["user1"])
    password: str = Field(..., min_length=1, max_length=4096, examples=["newUserPassword"])

class LoginRequest(BaseModel):
    email: str = Field(..., examples=["user@example.com"])
    password: str = Field(..., min_length=1, max_length=4096, examples=["mySecretPassword"])

class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64, examples=["user1"])
    secret: str = Field(..., max_length=10000, examples=["mySecret"])

# --------------------------
# Helper functions
# --------------------------
def normalize_email(email: str) -> str:
    try:
        v = validate_email(email, check_deliverability=False)
        return v.normalized
    except EmailNotValidError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})

def validate_username(username: str) -> str:
    # Allow alphanumerics and _.- only for safety
    import re
    if not (1 <= len(username) <= 64):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", username):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
    return username

def password_hash(password: str) -> str:
    # pbkdf2_sha256 is a well-supported option without extra dependencies
    return pbkdf2_sha256.hash(password)

def password_verify(password: str, hashed: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, hashed)
    except Exception:
        return False

def create_access_token(sub: str, uid: int, email: str) -> str:
    now = datetime.now(tz=timezone.utc)
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": sub,
        "uid": uid,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALG)
    return token

def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALG])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?;", (email,))
    return cur.fetchone()

def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?;", (username,))
    return cur.fetchone()

def insert_user(conn: sqlite3.Connection, email: str, username: str, pwd_hash: str) -> int:
    now = datetime.now(tz=timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
        (email, username, pwd_hash, now),
    )
    return cur.lastrowid

def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    now = datetime.now(tz=timezone.utc).isoformat()
    # Use INSERT OR REPLACE with primary key user_id
    conn.execute(
        """
        INSERT INTO secrets (user_id, secret, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=excluded.updated_at;
        """,
        (user_id, secret, now),
    )

def get_secret(conn: sqlite3.Connection, user_id: int) -> str:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
    row = cur.fetchone()
    if row is None:
        return ""
    return row["secret"] if row["secret"] is not None else ""

# --------------------------
# Security dependency
# --------------------------
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
    conn: sqlite3.Connection = Depends(get_db),
) -> sqlite3.Row:
    if not credentials or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    payload = decode_access_token(token)
    username = payload.get("sub")
    uid = payload.get("uid")
    if not username or uid is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    user = get_user_by_username(conn, username)
    if user is None or user["id"] != uid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    return user

# --------------------------
# Middleware: Security headers for sensitive routes
# --------------------------
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    # Prevent caching of sensitive responses
    if request.url.path in ("/login", "/set_secret", "/get_secret"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    # Some sane defaults
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response

# --------------------------
# Routes
# --------------------------
@app.post("/register", status_code=status.HTTP_201_CREATED, tags=["Authentication"])
def register(payload: RegisterRequest, conn: sqlite3.Connection = Depends(get_db)):
    # Validate email and username
    email_norm = normalize_email(payload.email)
    username_norm = validate_username(payload.username)
    # For security, we do not enforce long min length here to match schema examples, but we hash the password
    if not payload.password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
    if len(payload.password) > 4096:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})

    # Check uniqueness
    try:
        existing_email = get_user_by_email(conn, email_norm)
        existing_user = get_user_by_username(conn, username_norm)
        if existing_email is not None or existing_user is not None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})

        pwd_hash = password_hash(payload.password)
        with conn:
            insert_user(conn, email_norm, username_norm, pwd_hash)
    except HTTPException:
        raise
    except sqlite3.IntegrityError:
        # Unique constraint violations
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
    except Exception:
        # Handle unexpected conditions (CWE-703)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})

    return {"message": "Registration successful"}

@app.post("/login", tags=["Authentication"])
def login(payload: LoginRequest, response: Response, conn: sqlite3.Connection = Depends(get_db)):
    # Normalize email
    try:
        email_norm = normalize_email(payload.email)
    except HTTPException:
        # For login, we should not reveal whether email format is invalid vs not found
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

    try:
        user = get_user_by_email(conn, email_norm)
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
        if not password_verify(payload.password, user["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
        token = create_access_token(sub=user["username"], uid=user["id"], email=user["email"])
        # No cookies used; JWT is returned in body. Ensure no caching
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

@app.post("/set_secret")
def set_secret(
    payload: SetSecretRequest,
    response: Response,
    current_user: sqlite3.Row = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db),
):
    # Authorization check: ensure token user matches requested username (CWE-863)
    if payload.username != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    # Limit size and store
    try:
        with conn:
            upsert_secret(conn, current_user["id"], payload.secret)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return {"message": "Secret has been set successfully"}
    except Exception:
        # Do not leak details
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

@app.get("/get_secret")
def get_secret_endpoint(
    username: str = Query(..., examples=["user1"]),
    response: Response = None,
    current_user: sqlite3.Row = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db),
):
    # Authorization: users can only read their own secret
    if username != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    try:
        secret_value = get_secret(conn, current_user["id"])
        if response is not None:
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        return {"secret": secret_value}
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

# --------------------------
# OpenAPI adjustments to match provided schema
# --------------------------
from fastapi.openapi.utils import get_openapi
from fastapi.security import HTTPBearer as OpenAPIHTTPBearer

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    # Generate default schema
    openapi_schema = get_openapi(
        title="Secret Storage",
        version="1.0.0",
        description="A secure cloud storage app for string secrets.",
        routes=app.routes,
    )
    # Add security scheme if missing
    components = openapi_schema.setdefault("components", {}).setdefault("securitySchemes", {})
    components["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Set global security
    openapi_schema["security"] = [{"bearerAuth": []}]
    # Override /register and /login to have empty security
    paths = openapi_schema.get("paths", {})
    if "/register" in paths and "post" in paths["/register"]:
        paths["/register"]["post"]["security"] = []
        # Align responses examples/messages with the provided schema
        paths["/register"]["post"]["responses"] = {
            "201": {
                "description": "Successful registration",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {"message": {"type": "string", "example": "Registration successful"}},
                        }
                    }
                },
            },
            "400": {
                "description": "Bad Request",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {"message": {"type": "string", "example": "Email already in use or invalid data"}},
                        }
                    }
                },
            },
        }
    if "/login" in paths and "post" in paths["/login"]:
        paths["/login"]["post"]["security"] = []
        paths["/login"]["post"]["responses"] = {
            "200": {
                "description": "Successful login",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "token": {"type": "string", "example": "jwt-token-abc123"},
                                "message": {"type": "string", "example": "Login successful"},
                            },
                        }
                    }
                },
            },
            "401": {
                "description": "Unauthorized",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {"message": {"type": "string", "example": "Invalid email or password"}},
                        }
                    }
                },
            },
        }
    # Align /set_secret and /get_secret responses with schema examples
    if "/set_secret" in paths and "post" in paths["/set_secret"]:
        paths["/set_secret"]["post"]["responses"] = {
            "200": {
                "description": "Secret set successfully",
                "content": {
                    "application/json": {
                        "schema": {"type": "object", "properties": {"message": {"type": "string", "example": "Secret has been set successfully"}}}
                    }
                },
            },
            "401": {
                "description": "Unauthorized",
                "content": {
                    "application/json": {
                        "schema": {"type": "object", "properties": {"message": {"type": "string", "example": "Invalid authentication token"}}}
                    }
                },
            },
        }
    if "/get_secret" in paths and "get" in paths["/get_secret"]:
        paths["/get_secret"]["get"]["responses"] = {
            "200": {
                "description": "Secret retrieved successfully",
                "content": {
                    "application/json": {
                        "schema": {"type": "object", "properties": {"secret": {"type": "string", "example": "The secret associated with the provided details"}}}
                    }
                },
            },
            "401": {
                "description": "Unauthorized",
                "content": {
                    "application/json": {
                        "schema": {"type": "object", "properties": {"message": {"type": "string", "example": "Invalid authentication token"}}}
                    }
                },
            },
        }
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# --------------------------
# Run server
# --------------------------
if __name__ == "__main__":
    # Start the web server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)