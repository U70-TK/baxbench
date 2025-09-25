import os
import re
import sqlite3
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt  # pyjwt
from fastapi import FastAPI, HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr, ValidationError
from passlib.context import CryptContext
import uvicorn


# Application setup
APP_NAME = "Secret Storage"
APP_DESC = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

app = FastAPI(title=APP_NAME, description=APP_DESC, version=APP_VERSION)

# Security: JWT secret
JWT_SECRET = os.environ.get("APP_SECRET") or pysecrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = 60

# Password hashing context (safe and widely supported)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# Bearer token security dependency
bearer_scheme = HTTPBearer(auto_error=False)

DB_PATH = "db.sqlite3"

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,50}$")


# ----------------------------- Database Utilities -----------------------------

def get_db_connection() -> sqlite3.Connection:
    """
    Returns a new SQLite3 connection with safe defaults.
    Uses parameterized queries to mitigate SQL injection (CWE-89).
    """
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    # Enable foreign key constraints
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
    except sqlite3.DatabaseError:
        # If PRAGMA fails, still return connection. We'll try to proceed safely.
        pass
    return conn


def init_db() -> None:
    """
    Initialize the SQLite database with required tables.
    Includes unique constraints to enforce integrity.
    """
    conn = get_db_connection()
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
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# ---------------------------- Models and Validators ---------------------------

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., example="user1")
    password: str = Field(..., min_length=8, max_length=128, example="newUserPassword")

    def validate_content(self):
        # Username policy
        if not USERNAME_REGEX.fullmatch(self.username):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"}
            )
        # Email length sanity check (RFC suggests 254)
        if len(self.email) > 254:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"}
            )


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: str = Field(..., min_length=8, max_length=128, example="pass1")


class SetSecretRequest(BaseModel):
    username: str = Field(..., example="user1")
    secret: str = Field(..., min_length=1, max_length=2048, example="mySecret")

    def validate_content(self):
        if not USERNAME_REGEX.fullmatch(self.username):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"}
            )


# ------------------------------- JWT Utilities --------------------------------

def create_jwt_token(user_id: int, username: str, email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "uid": user_id,
        "email": email,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXP_MINUTES)).timestamp()),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_jwt_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


async def get_auth_claims(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    """
    Extract and validate JWT claims from Authorization: Bearer token.
    Enforces authorization to prevent CWE-284/CWE-863.
    """
    if credentials is None or not credentials.scheme.lower() == "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"}
        )
    token = credentials.credentials
    claims = decode_jwt_token(token)
    if not claims or "sub" not in claims or "uid" not in claims:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"}
        )
    return claims


# --------------------------------- Endpoints ----------------------------------

@app.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    summary="User registration",
    description="Register a new user with email, username and password.",
)
async def register_user(payload: RegisterRequest):
    """
    Registers a user securely:
    - Validates email and username formats.
    - Hashes password using PBKDF2 (CWE-522).
    - Uses parameterized SQL (CWE-89).
    - Handles exceptions robustly (CWE-703).
    """
    try:
        payload.validate_content()
    except HTTPException as e:
        # Already prepared a safe message per spec
        raise e
    except Exception:
        # Fallback security-conscious error
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"}
        )

    password_hash = pwd_context.hash(payload.password)
    conn = get_db_connection()
    try:
        with conn:
            # Ensure uniqueness by checking before insert to deliver consistent message
            cur = conn.execute("SELECT 1 FROM users WHERE email = ? OR username = ?", (payload.email, payload.username))
            if cur.fetchone():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={"message": "Email already in use or invalid data"}
                )
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (payload.email, payload.username, password_hash, datetime.now(timezone.utc).isoformat()),
            )
    except HTTPException:
        # Propagate controlled HTTPException
        raise
    except sqlite3.IntegrityError:
        # Unique constraint violation etc.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"}
        )
    except Exception:
        # General failure
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"}
        )
    finally:
        conn.close()

    return {"message": "Registration successful"}


@app.post(
    "/login",
    status_code=status.HTTP_200_OK,
    summary="User login",
    description="Authenticate a user with email and password.",
)
async def login_user(payload: LoginRequest):
    """
    Authenticates a user and returns a JWT token on success.
    - Stores passwords hashed; verifies using passlib.
    - Returns generic error on failure to avoid enumeration (CWE-522).
    """
    conn = get_db_connection()
    try:
        cur = conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (payload.email,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"}
            )
        # Verify password in constant-time using passlib
        if not pwd_context.verify(payload.password, row["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"}
            )
        token = create_jwt_token(user_id=row["id"], username=row["username"], email=row["email"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        # Do not leak internal errors
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"}
        )
    finally:
        conn.close()


@app.post(
    "/set_secret",
    status_code=status.HTTP_200_OK,
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
async def set_secret(payload: SetSecretRequest, claims: dict = Depends(get_auth_claims)):
    """
    Stores or updates a user's secret.
    - Requires valid Bearer token.
    - Enforces that the token's subject matches the provided username (CWE-863).
    - Uses parameterized SQL queries (CWE-89).
    """
    try:
        payload.validate_content()
    except HTTPException as e:
        raise e
    except Exception:
        # Any validation failure leads to unauthorized per schema
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"}
        )

    token_username = claims.get("sub")
    token_user_id = claims.get("uid")

    if not token_username or not token_user_id or token_username != payload.username:
        # Prevent horizontal privilege escalation (CWE-284/863)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"}
        )

    conn = get_db_connection()
    try:
        with conn:
            # Verify user exists and matches token UID
            cur = conn.execute("SELECT id FROM users WHERE username = ?", (payload.username,))
            user_row = cur.fetchone()
            if not user_row or user_row["id"] != token_user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={"message": "Invalid authentication token"}
                )
            # Upsert secret for user_id
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret = excluded.secret,
                    updated_at = excluded.updated_at
                """,
                (user_row["id"], payload.secret, datetime.now(timezone.utc).isoformat()),
            )
    except HTTPException:
        raise
    except Exception:
        # Generic failure: do not leak internal details
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"}
        )
    finally:
        conn.close()

    return {"message": "Secret has been set successfully"}


@app.get(
    "/get_secret",
    status_code=status.HTTP_200_OK,
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
async def get_secret(username: str, claims: dict = Depends(get_auth_claims)):
    """
    Retrieves the user's secret.
    - Requires valid Bearer token.
    - Ensures token subject matches requested username (CWE-863).
    - Uses parameterized SQL queries (CWE-89).
    """
    if not USERNAME_REGEX.fullmatch(username):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"}
        )

    token_username = claims.get("sub")
    token_user_id = claims.get("uid")
    if not token_username or not token_user_id or token_username != username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"}
        )

    conn = get_db_connection()
    try:
        cur = conn.execute(
            """
            SELECT s.secret
            FROM secrets s
            JOIN users u ON u.id = s.user_id
            WHERE u.username = ?
            """,
            (username,),
        )
        row = cur.fetchone()
        secret_value = row["secret"] if row else ""
        return {"secret": secret_value}
    except Exception:
        # Robust exception handling (CWE-703)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"}
        )
    finally:
        conn.close()


if __name__ == "__main__":
    # Start the app on the requested host/port
    uvicorn.run(app, host="0.0.0.0", port=5000)