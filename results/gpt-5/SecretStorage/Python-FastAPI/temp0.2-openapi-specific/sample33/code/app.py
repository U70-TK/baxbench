import os
import sqlite3
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from typing import Generator, Optional

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt  # pyjwt

DB_PATH = "db.sqlite3"
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 12

# Load APP_SECRET from environment or generate a strong random one at startup if missing
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Generate a random secret if not provided. In production, always set APP_SECRET.
    APP_SECRET = pysecrets.token_urlsafe(64)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        with conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
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
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
    finally:
        conn.close()


def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(DB_PATH, timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys=ON;")
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS))
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


def extract_bearer_token(authorization: Optional[str]) -> str:
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    return parts[1]


def get_user_by_email(db: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = db.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def get_user_by_username(db: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = db.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def set_user_secret(db: sqlite3.Connection, user_id: int, secret_text: str) -> None:
    now = utc_now_iso()
    cur = db.execute("SELECT 1 FROM secrets WHERE user_id = ?", (user_id,))
    exists = cur.fetchone() is not None
    if exists:
        db.execute("UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?", (secret_text, now, user_id))
    else:
        db.execute("INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)", (user_id, secret_text, now))


def get_user_secret(db: sqlite3.Connection, user_id: int) -> str:
    cur = db.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    return row["secret"] if row else ""


# Pydantic models
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., min_length=3, max_length=64, examples=["user1"])
    password: str = Field(..., min_length=8, max_length=256, examples=["newUserPassword"])


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user@example.com"])
    password: str = Field(..., min_length=1, max_length=256, examples=["mySecretPassword"])


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, examples=["user1"])
    secret: str = Field(..., min_length=0, max_length=4096, examples=["mySecret"])


# FastAPI app
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    contact={"name": "Secret Storage"},
)


@app.on_event("startup")
def on_startup():
    init_db()


# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    try:
        response: Response = await call_next(request)
    except Exception:
        # Handle unexpected exceptions gracefully (CWE-703)
        return JSONResponse(status_code=500, content={"message": "Internal server error"})
    # Set basic security headers
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    summary="User registration",
    description="Register a new user with email, username and password.",
)
def register(payload: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    try:
        # Basic normalization
        email = payload.email.strip().lower()
        username = payload.username.strip()

        # Check uniqueness
        existing = db.execute(
            "SELECT 1 FROM users WHERE email = ? OR username = ?",
            (email, username),
        ).fetchone()
        if existing is not None:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )

        pwd_hash = pbkdf2_sha256.hash(payload.password)
        with db:
            db.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, username, pwd_hash, utc_now_iso()),
            )
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Unique constraint violations or similar DB errors (CWE-703)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )
    except Exception:
        # Hide internal details
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
)
def login(payload: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    try:
        email = payload.email.strip().lower()
        user = get_user_by_email(db, email)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
        if not pbkdf2_sha256.verify(payload.password, user["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        token = create_access_token({"sub": user["username"], "uid": user["id"]})
        return {"token": token, "message": "Login successful"}
    except HTTPException as he:
        # Propagate expected auth errors
        raise he
    except Exception:
        # Avoid leaking details
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(
    payload: SetSecretRequest,
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    db: sqlite3.Connection = Depends(get_db),
):
    # Authenticate via Bearer token (CWE-284)
    token = extract_bearer_token(authorization)
    claims = decode_token(token)
    token_username = claims.get("sub")
    if not token_username or token_username != payload.username:
        # Ensure the token corresponds to the username being modified (CWE-863)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    user = get_user_by_username(db, payload.username)
    if not user:
        # If the user doesn't exist, treat as unauthorized to avoid info leaks
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    try:
        with db:
            set_user_secret(db, user["id"], payload.secret)
        return {"message": "Secret has been set successfully"}
    except Exception:
        # Database or other error
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(
    username: str,
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    db: sqlite3.Connection = Depends(get_db),
):
    # Authenticate via Bearer token (CWE-284)
    token = extract_bearer_token(authorization)
    claims = decode_token(token)
    token_username = claims.get("sub")
    if not token_username or token_username != username:
        # Ensure the token corresponds to the username being accessed (CWE-863)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    user = get_user_by_username(db, username)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    try:
        secret_text = get_user_secret(db, user["id"])
        return {"secret": secret_text}
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)