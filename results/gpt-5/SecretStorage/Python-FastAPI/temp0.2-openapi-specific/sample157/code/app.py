import os
import re
import sqlite3
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr, ValidationError
from passlib.hash import pbkdf2_sha256
import jwt


# Constants and configuration
APP_NAME = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"
DB_PATH = "db.sqlite3"
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,50}$")
MAX_SECRET_LENGTH = 4096

# Load application secret securely
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to ephemeral secret if not provided; tokens will be invalid after restart
    APP_SECRET = pysecrets.token_urlsafe(64)


# FastAPI application
app = FastAPI(title=APP_NAME, description=APP_DESCRIPTION, version=APP_VERSION)


# Database utilities
def init_db():
    """
    Initialize the SQLite database with required tables and constraints.
    Ensures safe defaults to reduce the chance of concurrency-related exceptions.
    """
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30)
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        cur = conn.cursor()

        # Users table: unique email and username, store hashed password
        cur.execute(
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

        # Secrets table: one secret per user (user_id unique)
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret_text TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )

        conn.commit()
    except Exception:
        # In case of unexpected initialization errors, avoid leaking sensitive details.
        # Application will still try to operate; requests will surface errors appropriately.
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def get_db_connection():
    """
    Create a new SQLite connection per request. Using WAL mode with reasonable timeout
    helps mitigate lock contention. Row factory provides dict-like access.
    """
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


# Security utilities
def create_access_token(user_id: int, username: str) -> str:
    """
    Create a JWT access token with limited lifetime and minimal claims.
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "uid": user_id,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> Optional[dict]:
    """
    Decode and validate a JWT. Return claims dict if valid, else None.
    """
    try:
        claims = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        # Basic claim sanity checks
        if claims.get("type") != "access":
            return None
        if not isinstance(claims.get("uid"), int):
            return None
        if not isinstance(claims.get("sub"), str):
            return None
        return claims
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception:
        # Defensive: any unexpected decoding error results in invalid
        return None


def authenticate_request(request: Request, conn: sqlite3.Connection) -> Optional[sqlite3.Row]:
    """
    Authenticate request using Bearer token and return the associated user row if valid.
    """
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return None
    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        return None

    claims = decode_token(token)
    if not claims:
        return None

    try:
        cur = conn.cursor()
        cur.execute("SELECT id, email, username FROM users WHERE id = ? AND username = ?;", (claims["uid"], claims["sub"]))
        user = cur.fetchone()
        return user
    except Exception:
        return None


# Pydantic models with validation
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)

    def validate_username(self) -> Optional[str]:
        if not USERNAME_REGEX.fullmatch(self.username):
            return "Username must be 3-50 characters long and contain only letters, numbers, and underscores."
        return None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=128)


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    secret: str = Field(..., min_length=1, max_length=MAX_SECRET_LENGTH)

    def validate_username(self) -> Optional[str]:
        if not USERNAME_REGEX.fullmatch(self.username):
            return "Username must be 3-50 characters long and contain only letters, numbers, and underscores."
        return None


# Startup
init_db()


# Routes implementation

@app.post("/register")
async def register(request: Request):
    """
    Register a new user with email, username and password.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

    try:
        data = RegisterRequest(**body)
    except ValidationError:
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

    username_error = data.validate_username()
    if username_error:
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

    # Hash password with PBKDF2-SHA256 (passlib)
    try:
        password_hash = pbkdf2_sha256.hash(data.password)
    except Exception:
        # Fallback if hashing fails unexpectedly
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        # Check for existing email or username
        cur.execute("SELECT 1 FROM users WHERE email = ?;", (data.email,))
        if cur.fetchone():
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
        cur.execute("SELECT 1 FROM users WHERE username = ?;", (data.username,))
        if cur.fetchone():
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        created_at = datetime.now(timezone.utc).isoformat()
        cur.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (data.email, data.username, password_hash, created_at),
        )
        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except Exception:
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.post("/login")
async def login(request: Request):
    """
    Authenticate a user with email and password.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

    try:
        data = LoginRequest(**body)
    except ValidationError:
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?;", (data.email,))
        row = cur.fetchone()
        if not row:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

        # Verify password securely
        try:
            if not pbkdf2_sha256.verify(data.password, row["password_hash"]):
                return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        except Exception:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

        token = create_access_token(user_id=row["id"], username=row["username"])
        return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})
    except Exception:
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.post("/set_secret")
async def set_secret(request: Request):
    """
    Save a secret on the server using the username and the secret text.
    Requires a valid Bearer token; only the owner can set their secret.
    """
    conn = get_db_connection()
    try:
        # Authenticate via bearer token
        user = authenticate_request(request, conn)
        if user is None:
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

        try:
            data = SetSecretRequest(**body)
        except ValidationError:
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

        username_error = data.validate_username()
        if username_error:
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

        # Authorization: ensure the token identity matches the username provided
        if data.username != user["username"]:
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

        # Upsert the secret
        cur = conn.cursor()
        # Retrieve user id to ensure mapping
        user_id = user["id"]

        cur.execute("SELECT id FROM secrets WHERE user_id = ?;", (user_id,))
        existing = cur.fetchone()
        now_iso = datetime.now(timezone.utc).isoformat()

        if existing:
            cur.execute(
                "UPDATE secrets SET secret_text = ?, updated_at = ? WHERE user_id = ?;",
                (data.secret, now_iso, user_id),
            )
        else:
            cur.execute(
                "INSERT INTO secrets (user_id, secret_text, updated_at) VALUES (?, ?, ?);",
                (user_id, data.secret, now_iso),
            )

        return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})
    except Exception:
        # On unexpected exceptions, avoid leaking details and return standard unauthorized message
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.get("/get_secret")
async def get_secret(request: Request, username: str):
    """
    Retrieve a secret based on the provided username.
    Requires a valid Bearer token; only the owner can retrieve their secret.
    """
    # Validate username format early to reduce enumeration risks
    if not USERNAME_REGEX.fullmatch(username):
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        user = authenticate_request(request, conn)
        if user is None:
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

        # Authorization: ensure the token identity matches the requested username
        if username != user["username"]:
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

        cur = conn.cursor()
        cur.execute("SELECT secret_text FROM secrets WHERE user_id = ?;", (user["id"],))
        row = cur.fetchone()
        # If no secret set yet, return empty string to conform to a successful retrieval
        secret_text = row["secret_text"] if row else ""
        return JSONResponse(status_code=200, content={"secret": secret_text})
    except Exception:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    finally:
        try:
            conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)