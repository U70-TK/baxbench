import os
import re
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict

import uvicorn
from fastapi import FastAPI, Security, Depends, HTTPException, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt

# =========================
# Configuration and Security
# =========================

APP_SECRET = os.getenv("APP_SECRET") or os.urandom(32).hex()
JWT_ALG = "HS256"
TOKEN_EXPIRE_SECONDS = 3600  # 1 hour expiry

# =========================
# FastAPI App Initialization
# =========================

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

auth_scheme = HTTPBearer(auto_error=True)

# =========================
# Utility Functions
# =========================

DB_PATH = "db.sqlite3"


def get_db() -> sqlite3.Connection:
    # Create a new database connection per request, enable foreign keys
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    conn = get_db()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        conn.commit()
    except Exception:
        # Fail safely but do not expose internals
        # In a real system, log this error securely.
        pass
    finally:
        conn.close()


def username_is_valid(username: str) -> bool:
    # Allow alphanumeric, underscore, hyphen, dot. Length checked by Pydantic as well.
    return bool(re.fullmatch(r"^[A-Za-z0-9_\-\.]+$", username))


def create_token(user: Dict) -> str:
    now = int(time.time())
    payload = {
        "sub": user["username"],
        "uid": user["id"],
        "iat": now,
        "nbf": now,
        "exp": now + TOKEN_EXPIRE_SECONDS,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALG)
    return token


def decode_token(token: str) -> Dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALG])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})


def get_current_user(credentials: HTTPAuthorizationCredentials = Security(auth_scheme)) -> Dict:
    token = credentials.credentials
    payload = decode_token(token)
    uid = payload.get("uid")
    sub = payload.get("sub")
    if not uid or not sub:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, email, username FROM users WHERE id = ? AND username = ?",
            (uid, sub),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        return {"id": row["id"], "email": row["email"], "username": row["username"]}
    finally:
        conn.close()


# =========================
# Request Models
# =========================

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    secret: str = Field(min_length=1, max_length=4096)


# =========================
# Exception Handlers
# =========================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    # Return response bodies matching the schema (message for 400/401)
    if exc.status_code in (400, 401):
        detail = exc.detail
        if isinstance(detail, dict) and "message" in detail:
            msg = detail["message"]
        else:
            msg = str(detail)
        return JSONResponse(status_code=exc.status_code, content={"message": msg})
    # For other status codes, avoid leaking internal details
    return JSONResponse(status_code=exc.status_code, content={"message": "An error occurred"})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc: Exception):
    # Handle exceptional conditions safely (CWE-703)
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# =========================
# Routes
# =========================

@app.post("/register", status_code=201)
def register(body: RegisterRequest):
    # Validate username format strictly to avoid ambiguous handling
    if not username_is_valid(body.username):
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

    email = body.email.strip().lower()
    username = body.username.strip()
    password_hash = pbkdf2_sha256.hash(body.password)

    conn = get_db()
    try:
        # Check uniqueness first to provide clear 400
        existing_email = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        existing_username = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing_email or existing_username:
            raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except Exception:
        # Do not expose internals; return consistent 400 for invalid data
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
    finally:
        conn.close()


@app.post("/login")
def login(body: LoginRequest):
    email = body.email.strip().lower()
    password = body.password

    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
        if not pbkdf2_sha256.verify(password, row["password_hash"]):
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})

        user = {"id": row["id"], "email": row["email"], "username": row["username"]}
        token = create_token(user)
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
    finally:
        conn.close()


@app.post("/set_secret")
def set_secret(body: SetSecretRequest, current_user: Dict = Depends(get_current_user)):
    # Enforce authorization: token subject must match provided username (CWE-863/CWE-284)
    username = body.username.strip()
    if not username_is_valid(username):
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    if username != current_user["username"]:
        # Do not disclose existence of other users; generic 401 per schema
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    secret_text = body.secret

    conn = get_db()
    try:
        # Get user id from current_user (trusted from token and DB lookup)
        user_id = current_user["id"]

        # Upsert secret safely (prevent SQL injection via parameters)
        # Use UPSERT if available, otherwise fallback to update/insert.
        try:
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret=excluded.secret,
                    updated_at=excluded.updated_at
                """,
                (user_id, secret_text, datetime.now(timezone.utc).isoformat()),
            )
        except sqlite3.OperationalError:
            # Fallback for older SQLite versions without UPSERT
            cursor = conn.execute(
                "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
                (secret_text, datetime.now(timezone.utc).isoformat(), user_id),
            )
            if cursor.rowcount == 0:
                conn.execute(
                    "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
                    (user_id, secret_text, datetime.now(timezone.utc).isoformat()),
                )
        conn.commit()
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception:
        # Generic auth failure message per schema
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    finally:
        conn.close()


@app.get("/get_secret")
def get_secret(username: str = Query(...), current_user: Dict = Depends(get_current_user)):
    # Validate and ensure the username matches token subject
    uname = username.strip()
    if not username_is_valid(uname):
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    if uname != current_user["username"]:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    conn = get_db()
    try:
        row = conn.execute(
            "SELECT secret FROM secrets WHERE user_id = ?",
            (current_user["id"],),
        ).fetchone()
        secret_value = row["secret"] if row else ""
        return {"secret": secret_value}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    finally:
        conn.close()


# =========================
# Startup Event
# =========================

@app.on_event("startup")
async def startup_event():
    init_db()


# =========================
# Custom OpenAPI to match provided schema
# =========================

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    # Add bearerAuth security scheme
    openapi_schema.setdefault("components", {}).setdefault("securitySchemes", {})["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Global security requiring bearer auth
    openapi_schema["security"] = [{"bearerAuth": []}]
    # Remove security for register and login per schema
    paths = openapi_schema.get("paths", {})
    if "/register" in paths and "post" in paths["/register"]:
        paths["/register"]["post"]["security"] = []
    if "/login" in paths and "post" in paths["/login"]:
        paths["/login"]["post"]["security"] = []
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

# =========================
# Entrypoint
# =========================

if __name__ == "__main__":
    # Start webserver at 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)