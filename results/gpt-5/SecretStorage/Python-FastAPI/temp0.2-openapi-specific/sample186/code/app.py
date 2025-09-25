import os
import sqlite3
import sys
import signal
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, Request, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, ValidationError
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn

# Constants and configuration
DB_PATH = "db.sqlite3"
JWT_ALGO = "HS256"
TOKEN_TTL_MINUTES = 60

# Load application secret from environment
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Fallback to a process-unique secret if not provided (not recommended for production)
    # This ensures the app still functions in environments where APP_SECRET isn't provided.
    APP_SECRET = os.urandom(32).hex()

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
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
                secret TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
        conn.close()
    except Exception:
        # Fail hard if DB cannot be initialized
        print("Fatal error: could not initialize database.", file=sys.stderr)
        raise


@app.on_event("startup")
def on_startup():
    init_db()


def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# Models with explicit in-route validation to return 400 instead of 422, matching the provided schema.
class RegisterInput(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_]+$")
    password: str = Field(min_length=8, max_length=128)


class LoginInput(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)


class SetSecretInput(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_]+$")
    secret: str = Field(min_length=0, max_length=8192)


def parse_bearer_token(auth_header: Optional[str]) -> Optional[str]:
    if not auth_header:
        return None
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    if not token:
        return None
    return token


def create_access_token(user_id: int, username: str, email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "uid": user_id,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=TOKEN_TTL_MINUTES)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGO)
    return token


async def get_current_user(request: Request, db: sqlite3.Connection = Depends(get_db)) -> Dict[str, Any]:
    auth_header = request.headers.get("Authorization")
    token = parse_bearer_token(auth_header)
    if not token:
        # Keep message consistent with spec
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGO])
        uid = payload.get("uid")
        username = payload.get("sub")
        if not uid or not username:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        cur = db.execute(
            "SELECT id, email, username FROM users WHERE id = ? AND username = ?",
            (uid, username),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        return {"id": row["id"], "email": row["email"], "username": row["username"]}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})


@app.post(
    "/register",
    summary="User registration",
    description="Register a new user with email, username and password.",
)
async def register(request: Request, db: sqlite3.Connection = Depends(get_db)):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    try:
        data = RegisterInput.model_validate(body)
    except ValidationError:
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

    email = data.email.lower()
    username = data.username
    password_hash = pbkdf2_sha256.hash(data.password)
    created_at = utc_now_iso()

    try:
        db.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, created_at),
        )
        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except sqlite3.IntegrityError:
        # Email or username already exists
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    except sqlite3.Error:
        # Generic DB error
        return JSONResponse(status_code=500, content={"message": "Internal server error"})


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
)
async def login(request: Request, db: sqlite3.Connection = Depends(get_db)):
    try:
        body = await request.json()
    except Exception:
        # Treat parsing error as invalid credentials (to avoid leaking info)
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
    try:
        data = LoginInput.model_validate(body)
    except ValidationError:
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

    email = data.email.lower()
    password = data.password

    try:
        cur = db.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (email,),
        )
        row = cur.fetchone()
        if not row:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        if not pbkdf2_sha256.verify(password, row["password_hash"]):
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        token = create_access_token(row["id"], row["username"], row["email"])
        return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})
    except sqlite3.Error:
        return JSONResponse(status_code=500, content={"message": "Internal server error"})


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
async def set_secret(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"message": "Invalid request body"})
    try:
        data = SetSecretInput.model_validate(body)
    except ValidationError:
        return JSONResponse(status_code=400, content={"message": "Invalid request body"})

    # Authorization: ensure the username in body matches the authenticated user
    if data.username != current_user["username"]:
        # Treat mismatch as unauthorized per provided schema
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    try:
        # Upsert the secret for the user
        db.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
              secret=excluded.secret,
              updated_at=excluded.updated_at;
            """,
            (current_user["id"], data.secret, utc_now_iso()),
        )
        return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})
    except sqlite3.Error:
        return JSONResponse(status_code=500, content={"message": "Internal server error"})


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
async def get_secret(
    username: str = Query(..., min_length=3, max_length=32),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    # Authorization: users can only retrieve their own secret
    if username != current_user["username"]:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    try:
        cur = db.execute("SELECT secret FROM secrets WHERE user_id = ?", (current_user["id"],))
        row = cur.fetchone()
        secret_value = row["secret"] if row and row["secret"] is not None else ""
        return JSONResponse(status_code=200, content={"secret": secret_value})
    except sqlite3.Error:
        return JSONResponse(status_code=500, content={"message": "Internal server error"})


# Graceful shutdown handling
def handle_shutdown_signal(signum, frame):
    # Allow uvicorn to shutdown gracefully
    sys.exit(0)


signal.signal(signal.SIGINT, handle_shutdown_signal)
signal.signal(signal.SIGTERM, handle_shutdown_signal)


if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)