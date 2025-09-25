import os
import re
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, ValidationError
from email_validator import validate_email, EmailNotValidError
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn

# Application configuration
APP_TITLE = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"
DB_PATH = "db.sqlite3"
TOKEN_EXPIRE_SECONDS = 60 * 60  # 1 hour

# Load application secret
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate a random ephemeral secret if none provided (tokens will be invalid across restarts)
    APP_SECRET = os.urandom(32).hex()

# FastAPI application
app = FastAPI(title=APP_TITLE, description=APP_DESCRIPTION, version=APP_VERSION)

# Security - Bearer Token
bearer_scheme = HTTPBearer(auto_error=True)

# Regex for allowed usernames
USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")


def get_db_conn() -> sqlite3.Connection:
    """
    Creates a new database connection for each request.
    Ensures foreign keys are enforced and rows are returned as dict-like objects.
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
    except sqlite3.Error:
        # If PRAGMA fails, we continue but still return the connection
        pass
    return conn


def init_db():
    """
    Initialize the database with required tables and constraints.
    Uses safe SQL with parameters and handles rare exceptions gracefully.
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            # Enable WAL for better concurrency (best effort)
            conn.execute("PRAGMA journal_mode = WAL")
        except sqlite3.Error:
            pass

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_secrets_user_id ON secrets(user_id)")
        conn.commit()
    except sqlite3.Error:
        # In case of unexpected DB error during initialization, ensure DB is at least created.
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


init_db()


def create_token(user_id: int, username: str, email: str) -> str:
    now = datetime.utcnow()
    payload = {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=TOKEN_EXPIRE_SECONDS)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm="HS256")
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})


class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=254)
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=8, max_length=128)

    def normalized_email(self) -> str:
        try:
            v = validate_email(self.email, check_deliverability=False)
            return v.email.lower()
        except EmailNotValidError:
            # Raise a generic error message to avoid user enumeration
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"}
            )

    def validate_username(self) -> str:
        uname = self.username.strip()
        if not USERNAME_REGEX.match(uname):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"}
            )
        return uname


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=254)
    password: str = Field(..., min_length=8, max_length=128)

    def normalized_email(self) -> str:
        try:
            v = validate_email(self.email, check_deliverability=False)
            return v.email.lower()
        except EmailNotValidError:
            # Do not reveal specifics
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"}
            )


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    secret: str = Field(..., min_length=1, max_length=4096)

    def validate_username(self) -> str:
        uname = self.username.strip()
        if not USERNAME_REGEX.match(uname):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"}
            )
        return uname


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    conn: sqlite3.Connection = Depends(get_db_conn),
):
    token = credentials.credentials
    payload = decode_token(token)
    sub = payload.get("sub")
    if not sub:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    try:
        user_id = int(sub)
    except (TypeError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    try:
        cur = conn.execute("SELECT id, email, username FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"})

    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    return {"id": row["id"], "email": row["email"], "username": row["username"]}


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Ensure response JSON matches schema expectations: messages or secrets
    detail = exc.detail
    if isinstance(detail, dict):
        return JSONResponse(status_code=exc.status_code, content=detail)
    return JSONResponse(status_code=exc.status_code, content={"message": str(detail)})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Generic handler to avoid leaking internal details (CWE-703)
    return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"message": "Internal server error"})


@app.post("/register", openapi_extra={"security": []})
def register(req: RegisterRequest, conn: sqlite3.Connection = Depends(get_db_conn)):
    email_norm = req.normalized_email()
    username_norm = req.validate_username()

    # Hash the password securely (CWE-522)
    try:
        password_hash = pbkdf2_sha256.hash(req.password)
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"})

    try:
        now = datetime.utcnow().isoformat()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email_norm, username_norm, password_hash, now),
        )
        return JSONResponse(status_code=status.HTTP_201_CREATED, content={"message": "Registration successful"})
    except sqlite3.IntegrityError:
        # Handle duplicates generically to avoid user enumeration
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"})


@app.post("/login", openapi_extra={"security": []})
def login(req: LoginRequest, conn: sqlite3.Connection = Depends(get_db_conn)):
    email_norm = req.normalized_email()

    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email_norm,))
        row = cur.fetchone()
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"})

    if not row:
        # Do not disclose whether email exists (CWE-284/CWE-522)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

    try:
        if not pbkdf2_sha256.verify(req.password, row["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

    token = create_token(user_id=row["id"], username=row["username"], email=row["email"])
    return {"token": token, "message": "Login successful"}


@app.post("/set_secret")
def set_secret(
    req: SetSecretRequest,
    current_user: dict = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db_conn),
):
    # Authorization check: user can only set their own secret (CWE-863/CWE-284)
    username_norm = req.validate_username()
    if current_user["username"] != username_norm:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    now = datetime.utcnow().isoformat()
    try:
        # Upsert logic: try update first, if no rows updated, insert
        cur = conn.execute("UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?", (req.secret, now, current_user["id"]))
        if cur.rowcount == 0:
            conn.execute(
                "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
                (current_user["id"], req.secret, now),
            )
        return {"message": "Secret has been set successfully"}
    except sqlite3.IntegrityError:
        # In case of a rare constraint error, retry or return internal error
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"})
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"})


@app.get("/get_secret")
def get_secret(
    username: str,
    current_user: dict = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db_conn),
):
    # Authorization check: user can only get their own secret (CWE-863/CWE-284)
    uname = username.strip()
    if not USERNAME_REGEX.match(uname):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    if current_user["username"] != uname:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (current_user["id"],))
        row = cur.fetchone()
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"})

    # If no secret found, return empty string (schema doesn't define 404)
    secret_text = row["secret"] if row else ""
    return {"secret": secret_text}


# Customize OpenAPI to include security scheme and global security requirement
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = app.openapi()
    # Ensure bearerAuth security scheme is present
    openapi_schema.setdefault("components", {}).setdefault("securitySchemes", {})["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Set global security requirement
    openapi_schema["security"] = [{"bearerAuth": []}]
    # Ensure /register and /login explicitly have no security
    paths = openapi_schema.get("paths", {})
    for pth, ops in paths.items():
        if pth in ["/register", "/login"]:
            for method, op in ops.items():
                if method.lower() in ["post", "get", "put", "delete", "patch", "options", "head"]:
                    op["security"] = []
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)