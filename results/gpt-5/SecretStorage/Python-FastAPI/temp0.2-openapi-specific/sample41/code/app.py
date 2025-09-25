import os
import re
import sys
import sqlite3
import datetime
from typing import Optional, Tuple, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, status, Request, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, field_validator
import uvicorn
import jwt  # pyjwt
from passlib.context import CryptContext
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

# Configuration
DB_PATH = "db.sqlite3"
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Generate an ephemeral secret if not provided (tokens won't survive restarts).
    # Prefer setting APP_SECRET via environment for production.
    APP_SECRET = os.urandom(32).hex()

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 60 * 60  # 1 hour

# Security helpers
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
bearer_scheme = HTTPBearer(description="JWT Authorization header using the Bearer scheme.")

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


# Database utilities
def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Ensure foreign keys are enforced
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
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
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        # Helpful indices
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        conn.commit()
    except sqlite3.Error as e:
        # Fail fast if DB can't be initialized
        print(f"Database initialization error: {e}", file=sys.stderr)
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.on_event("startup")
def on_startup():
    init_db()


# Pydantic models for request/response
USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,30}$")


class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., examples=["user1"])
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not USERNAME_REGEX.fullmatch(v):
            raise ValueError("Username must be 3-30 characters, alphanumeric or underscore.")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)


class SetSecretRequest(BaseModel):
    username: str
    secret: str = Field(..., min_length=1)


# Security-related helpers
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        return False


def create_access_token(username: str, user_id: int) -> str:
    now = datetime.datetime.utcnow()
    payload = {
        "sub": username,
        "uid": user_id,
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=ALGORITHM)
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def decode_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        # Basic checks
        if "sub" not in payload or "uid" not in payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def auth_dependency(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> Dict[str, Any]:
    token = credentials.credentials
    payload = decode_token(token)
    # Fetch the current user to ensure they still exist and match
    conn = get_db_connection()
    try:
        user = get_user_by_id(conn, int(payload.get("uid")))
        if not user or user["username"] != payload.get("sub"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        return {"id": user["id"], "email": user["email"], "username": user["username"]}
    finally:
        conn.close()


# Routes according to schema

@app.post(
    "/register",
    status_code=201,
    summary="User registration",
    description="Register a new user with email, username and password.",
)
def register(req: RegisterRequest):
    # Normalize email to lower-case
    email_norm = req.email.lower().strip()
    username = req.username.strip()

    conn = get_db_connection()
    try:
        # Check uniqueness
        existing_email = get_user_by_email(conn, email_norm)
        existing_username = get_user_by_username(conn, username)
        if existing_email or existing_username:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )
        # Insert user
        now = datetime.datetime.utcnow().isoformat() + "Z"
        pw_hash = hash_password(req.password)
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email_norm, username, pw_hash, now),
        )
        conn.commit()
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Unique constraint violation or similar
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    except Exception:
        # Generic safe error response
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    finally:
        conn.close()


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
)
def login(req: LoginRequest):
    email_norm = req.email.lower().strip()
    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, email_norm)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )
        if not verify_password(req.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )
        token = create_access_token(username=user["username"], user_id=user["id"])
        return {"token": token, "message": "Login successful"}
    finally:
        conn.close()


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(req: SetSecretRequest, current_user: Dict[str, Any] = Depends(auth_dependency)):
    # Authorization: ensure the token subject matches the username provided
    if req.username.strip() != current_user["username"]:
        # Do not leak details, respond as invalid token per schema
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    conn = get_db_connection()
    try:
        now = datetime.datetime.utcnow().isoformat() + "Z"
        # Upsert the secret for this user
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=excluded.updated_at;
            """,
            (current_user["id"], req.secret, now),
        )
        conn.commit()
        return {"message": "Secret has been set successfully"}
    except sqlite3.Error:
        # Database error treated as unauthorized to avoid leaking details? Better 500, but schema constrains 401/200.
        # However to adhere to secure practices and visibility, we return 500 with generic message internally,
        # but since schema defines 401 only for unauthorized, we will return 500 gracefully.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "An unexpected error occurred"},
        )
    finally:
        conn.close()


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(username: str = Query(...), current_user: Dict[str, Any] = Depends(auth_dependency)):
    # Authorization: only allow users to retrieve their own secret
    if username.strip() != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (current_user["id"],))
        row = cur.fetchone()
        secret_value = row["secret"] if row else ""
        return {"secret": secret_value}
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "An unexpected error occurred"},
        )
    finally:
        conn.close()


# Run server
if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000 as requested
    uvicorn.run(app, host="0.0.0.0", port=5000)