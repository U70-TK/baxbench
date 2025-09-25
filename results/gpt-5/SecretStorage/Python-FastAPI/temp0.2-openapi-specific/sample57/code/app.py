import os
import re
import sqlite3
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import jwt
from fastapi import FastAPI, Header, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr
from passlib.hash import pbkdf2_sha256
import uvicorn


# Application setup
APP_TITLE = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"
DB_PATH = "db.sqlite3"
TOKEN_TTL_SECONDS = 3600  # 1 hour

# Load signing key
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate a strong ephemeral secret if none provided; recommended to set APP_SECRET in production
    APP_SECRET = pysecrets.token_urlsafe(64)


app = FastAPI(title=APP_TITLE, description=APP_DESCRIPTION, version=APP_VERSION)


# Utility functions
def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_email(email: str) -> str:
    return email.strip().lower()


def db_connect() -> sqlite3.Connection:
    # Create a new connection per request to avoid cross-thread issues
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)  # autocommit mode
    conn.row_factory = sqlite3.Row
    # SQLite recommended pragmas for safe concurrent reads/writes
    try:
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
    except sqlite3.Error:
        # Even if PRAGMAs fail, continue with defaults
        pass
    return conn


def init_db() -> None:
    conn = db_connect()
    try:
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
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
    finally:
        conn.close()


def create_jwt(user_id: int, username: str) -> str:
    iat = datetime.now(timezone.utc)
    exp = iat + timedelta(seconds=TOKEN_TTL_SECONDS)
    payload = {
        "sub": username,
        "uid": user_id,
        "iat": int(iat.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm="HS256")
    return token


def decode_jwt(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(
            token,
            APP_SECRET,
            algorithms=["HS256"],
            options={"require": ["exp", "iat"], "verify_exp": True},
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def fetch_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        return row
    except sqlite3.Error:
        return None


def fetch_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT id, email, username FROM users WHERE username = ?", (username,))
        return cur.fetchone()
    except sqlite3.Error:
        return None


def save_secret(conn: sqlite3.Connection, user_id: int, secret_text: str) -> bool:
    try:
        # Upsert-style logic: try update, if no row affected, insert
        cur = conn.execute(
            "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
            (secret_text, now_utc_iso(), user_id),
        )
        if cur.rowcount == 0:
            conn.execute(
                "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
                (user_id, secret_text, now_utc_iso()),
            )
        return True
    except sqlite3.Error:
        return False


def get_secret(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        if row is None:
            return None
        return row["secret"]
    except sqlite3.Error:
        return None


def auth_and_authorize(
    authorization_header: Optional[str],
    expected_username: str,
    conn: sqlite3.Connection,
) -> Tuple[Optional[int], Optional[JSONResponse]]:
    """
    Validates the Authorization header, decodes the JWT, and verifies that it authorizes access to expected_username.
    Returns (user_id, error_response) where error_response is not None if authorization fails.
    """
    if not authorization_header:
        return None, JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None, JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    token = parts[1]
    payload = decode_jwt(token)
    if not payload or "sub" not in payload or "uid" not in payload:
        return None, JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    token_username = payload.get("sub")
    token_uid = payload.get("uid")
    # Constant-time comparison to avoid leaking user identities via timing attacks
    if not isinstance(token_username, str) or not isinstance(expected_username, str):
        return None, JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    if not pysecrets.compare_digest(token_username, expected_username):
        return None, JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    # Verify user in DB and that uid/username pair is valid
    try:
        cur = conn.execute(
            "SELECT id FROM users WHERE id = ? AND username = ?",
            (int(token_uid), token_username),
        )
        row = cur.fetchone()
    except (sqlite3.Error, ValueError):
        row = None
    if row is None:
        return None, JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    return row["id"], None


# Request/Response models
USERNAME_REGEX = re.compile(r"^[a-z0-9_]{3,32}$")


class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., description="User email")
    username: str = Field(..., description="Username (lowercase letters, digits, underscore, 3-32 chars)")
    password: str = Field(..., min_length=8, description="Password (min 8 chars)")

    def validate(self) -> Optional[str]:
        # EmailStr from Pydantic already validates email format; normalize it
        if not USERNAME_REGEX.match(self.username.strip()):
            return "Email already in use or invalid data"
        if len(self.password) < 8:
            return "Email already in use or invalid data"
        return None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)


class LoginResponse(BaseModel):
    token: str
    message: str


class RegisterResponse(BaseModel):
    message: str


class SetSecretRequest(BaseModel):
    username: str = Field(..., description="Username", min_length=3, max_length=32)
    secret: str = Field(..., description="Secret text", min_length=1, max_length=4096)


class SetSecretResponse(BaseModel):
    message: str


class GetSecretResponse(BaseModel):
    secret: str


# Routes
@app.post("/register", response_model=RegisterResponse, status_code=201, tags=["Authentication"])
def register(payload: RegisterRequest):
    # Validate content
    validation_error = payload.validate()
    if validation_error:
        return JSONResponse(status_code=400, content={"message": validation_error})

    email = normalize_email(str(payload.email))
    username = payload.username.strip()
    password_hash = pbkdf2_sha256.hash(payload.password)

    conn = db_connect()
    try:
        # Check for existing email or username
        try:
            cur = conn.execute(
                "SELECT 1 FROM users WHERE email = ? OR username = ?",
                (email, username),
            )
            if cur.fetchone() is not None:
                return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
        except sqlite3.Error:
            # Hide internal details
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        # Insert new user
        try:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, username, password_hash, now_utc_iso()),
            )
        except sqlite3.IntegrityError:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
        except sqlite3.Error:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        return {"message": "Registration successful"}
    finally:
        conn.close()


@app.post("/login", response_model=LoginResponse, tags=["Authentication"])
def login(payload: LoginRequest):
    email = normalize_email(str(payload.email))
    password = payload.password

    conn = db_connect()
    try:
        user_row = fetch_user_by_email(conn, email)
        if user_row is None:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

        stored_hash = user_row["password_hash"]
        try:
            if not pbkdf2_sha256.verify(password, stored_hash):
                return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        except Exception:
            # Any issue verifying the password should not reveal details
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

        token = create_jwt(user_row["id"], user_row["username"])
        return {"token": token, "message": "Login successful"}
    finally:
        conn.close()


@app.post("/set_secret", response_model=SetSecretResponse)
def set_secret(payload: SetSecretRequest, authorization: Optional[str] = Header(default=None)):
    username = payload.username.strip()
    secret_text = payload.secret

    # Enforce reasonable secret size limit
    if len(secret_text) > 4096:
        # Do not leak details; treat as invalid token to avoid clues about system limits
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    conn = db_connect()
    try:
        user_id, error_resp = auth_and_authorize(authorization, username, conn)
        if error_resp is not None:
            return error_resp

        # Persist secret securely
        ok = save_secret(conn, user_id, secret_text)
        if not ok:
            # Fail safely without exposing internals
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

        return {"message": "Secret has been set successfully"}
    finally:
        conn.close()


@app.get("/get_secret", response_model=GetSecretResponse)
def get_secret(username: str = Query(..., min_length=3, max_length=32), authorization: Optional[str] = Header(default=None)):
    username = username.strip()

    conn = db_connect()
    try:
        # Authorize request
        user_id, error_resp = auth_and_authorize(authorization, username, conn)
        if error_resp is not None:
            return error_resp

        # Retrieve secret
        secret_value = get_secret(conn, user_id)
        if secret_value is None:
            # As the schema does not define a 404, return empty secret
            secret_value = ""

        return {"secret": secret_value}
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


if __name__ == "__main__":
    # Run the server at 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)