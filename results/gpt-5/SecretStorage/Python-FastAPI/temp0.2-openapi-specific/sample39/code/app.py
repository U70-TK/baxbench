import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Generator, Optional, Tuple

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Header, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr, constr, ValidationError
from passlib.hash import pbkdf2_sha256
import jwt

# App configuration
APP_TITLE = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

DB_PATH = "db.sqlite3"
JWT_ALG = "HS256"
JWT_EXPIRE_SECONDS = 3600  # 1 hour

# Load application secret
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fall back to a random, per-run secret for development/testing.
    # Note: Tokens will become invalid on restart if APP_SECRET is not set.
    APP_SECRET = os.urandom(32).hex()


# Database utilities
def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
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
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
    finally:
        conn.close()


# Pydantic models for requests/responses
UsernameType = constr(strip_whitespace=True, min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")

class RegisterRequest(BaseModel):
    email: EmailStr
    username: UsernameType
    password: constr(min_length=8, max_length=128)

class LoginRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=1, max_length=128)

class SetSecretRequest(BaseModel):
    username: UsernameType
    secret: constr(min_length=1, max_length=4096)

class MessageResponse(BaseModel):
    message: str

class TokenResponse(BaseModel):
    token: str
    message: str

class SecretResponse(BaseModel):
    secret: str


# Security / Auth helpers
def create_access_token(*, user_id: int, username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=JWT_EXPIRE_SECONDS)).timestamp()),
        "iss": APP_TITLE,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALG)
    return token

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALG], options={"require": ["exp", "iat", "sub"]})
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

def get_authorization_token(authorization: Optional[str]) -> str:
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    return parts[1]

def get_current_user(
    authorization: Optional[str] = Header(default=None),
    db: sqlite3.Connection = Depends(get_db),
) -> sqlite3.Row:
    token = get_authorization_token(authorization)
    payload = decode_token(token)
    user_id = payload.get("sub")
    username_claim = payload.get("username")
    if not user_id or not username_claim:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    cur = db.execute("SELECT id, email, username FROM users WHERE id = ?;", (user_id,))
    user = cur.fetchone()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    if user["username"] != username_claim:
        # Token username mismatch -> treat as invalid auth token
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    return user


# FastAPI app
app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

@app.on_event("startup")
def on_startup():
    init_db()


# Routes

@app.post("/register", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    email = body.email.strip().lower()
    username = body.username.strip()
    password = body.password

    # Hash the password with PBKDF2-SHA256
    try:
        password_hash = pbkdf2_sha256.hash(password)
    except Exception:
        # Defensive: in case hashing fails
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")

    # Insert user, enforcing unique email and username
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (email, username, password_hash, now_iso),
        )
        db.commit()
    except sqlite3.IntegrityError:
        # Email or username already taken
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")
    except Exception:
        # Unexpected DB error
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")

    return {"message": "Registration successful"}


@app.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    email = body.email.strip().lower()
    password = body.password

    try:
        cur = db.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?;", (email,))
        user = cur.fetchone()
    except Exception:
        # Database error should not leak details
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    if not user:
        # Do not reveal whether email exists
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    password_hash = user["password_hash"]
    try:
        if not pbkdf2_sha256.verify(password, password_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    except Exception:
        # Verification failure
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    token = create_access_token(user_id=int(user["id"]), username=user["username"])
    return {"token": token, "message": "Login successful"}


@app.post("/set_secret", response_model=MessageResponse)
def set_secret(
    body: SetSecretRequest,
    current_user: sqlite3.Row = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    request_username = body.username.strip()
    if request_username != current_user["username"]:
        # Prevent setting secrets for other users
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    secret_value = body.secret
    now_iso = datetime.now(timezone.utc).isoformat()

    try:
        db.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret = excluded.secret,
                updated_at = excluded.updated_at;
            """,
            (current_user["id"], secret_value, now_iso),
        )
        db.commit()
    except Exception:
        # Do not leak DB errors
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    return {"message": "Secret has been set successfully"}


@app.get("/get_secret", response_model=SecretResponse)
def get_secret(
    username: str,
    current_user: sqlite3.Row = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    if not isinstance(username, str) or len(username.strip()) == 0:
        # Minimal validation; schema defines username as string
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    if username != current_user["username"]:
        # Prevent reading other user's secret
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    try:
        cur = db.execute("SELECT secret FROM secrets WHERE user_id = ?;", (current_user["id"],))
        row = cur.fetchone()
    except Exception:
        # Treat DB errors as auth error per schema (only 200/401 are defined)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    if not row:
        # No secret set yet -> return empty string
        return {"secret": ""}

    return {"secret": row["secret"]}


# Custom exception handlers to conform response body shape
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Ensure all error responses have "message" field when it's an error scenario our schema defines
    detail = exc.detail if isinstance(exc.detail, str) else "An error occurred"
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": detail} if exc.status_code in (400, 401) else {"detail": detail},
    )


if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)