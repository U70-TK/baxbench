import os
import sqlite3
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from passlib.hash import pbkdf2_sha256
import jwt

# Configuration
DATABASE_PATH = "db.sqlite3"
ALGORITHM = "HS256"
SECRET_KEY = os.getenv("APP_SECRET") or secrets.token_urlsafe(64)  # Fallback is ephemeral
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
)

http_bearer = HTTPBearer(auto_error=False)


def get_db() -> sqlite3.Connection:
    """
    Get a new database connection with safe settings.
    Using a new connection per request reduces concurrency issues.
    """
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    # Enforce foreign key constraints
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    """
    Initialize database tables if they do not exist.
    Handle exceptional conditions gracefully (CWE-703).
    """
    try:
        conn = get_db()
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
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE
                );
                """
            )
    except sqlite3.Error as e:
        # Log error safely; do not expose sensitive info (CWE-703)
        print(f"Database initialization error: {e}")
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.on_event("startup")
def on_startup() -> None:
    init_db()


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a signed JWT token with an expiration time.
    """
    to_encode = data.copy()
    now = datetime.utcnow()
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"iat": now, "nbf": now, "exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decode and validate the access token, raising 401 on failure.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "access":
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


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(http_bearer)) -> sqlite3.Row:
    """
    Security dependency that enforces Bearer JWT authentication
    and loads the current user from the database.
    Prevents unauthorized access (CWE-284) and improper authorization (CWE-863).
    """
    if credentials is None or not credentials.scheme.lower() == "bearer" or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    token = credentials.credentials
    payload = decode_access_token(token)
    sub = payload.get("sub")
    username = payload.get("username")
    if sub is None or username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    try:
        user_id = int(sub)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    try:
        conn = get_db()
        cur = conn.execute("SELECT id, email, username FROM users WHERE id = ? AND username = ?", (user_id, username))
        user = cur.fetchone()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        return user
    except sqlite3.Error:
        # If DB error occurs here, treat as unauthorized for safety
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    finally:
        try:
            conn.close()
        except Exception:
            pass


# Pydantic models

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., min_length=3, max_length=50, example="user1")
    password: str = Field(..., min_length=8, max_length=128, example="newUserPassword")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: str = Field(..., min_length=8, max_length=128, example="pass1")


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, example="user1")
    secret: str = Field(..., min_length=1, max_length=4096, example="mySecret")


# Routes

@app.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
    summary="User registration",
    description="Register a new user with email, username and password.",
)
def register(req: RegisterRequest):
    """
    Register a new user with secure password hashing (CWE-522).
    Use parameterized queries to prevent SQL injection (CWE-89).
    Handle exceptional conditions safely (CWE-703).
    """
    # Hash password with a strong algorithm (no external deps required)
    password_hash = pbkdf2_sha256.hash(req.password)

    try:
        conn = get_db()
        with conn:
            # Check duplicates
            cur_email = conn.execute("SELECT id FROM users WHERE email = ?", (req.email,))
            if cur_email.fetchone() is not None:
                return {"message": "Email already in use or invalid data"}

            cur_username = conn.execute("SELECT id FROM users WHERE username = ?", (req.username,))
            if cur_username.fetchone() is not None:
                # To conform to the provided example message
                return {"message": "Email already in use or invalid data"}

            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (req.email, req.username, password_hash, datetime.utcnow().isoformat()),
            )
        return {"message": "Registration successful"}
    except sqlite3.Error:
        # Do not expose internal DB errors; respond with a generic bad request
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Email already in use or invalid data"},
        )
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.post(
    "/login",
    status_code=status.HTTP_200_OK,
    tags=["Authentication"],
    summary="User login",
    description="Authenticate a user with email and password.",
)
def login(req: LoginRequest):
    """
    Authenticate user and return a JWT token.
    Prevent credential leakage on error (CWE-522).
    """
    try:
        conn = get_db()
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (req.email,))
        user = cur.fetchone()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )

        if not pbkdf2_sha256.verify(req.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )

        token = create_access_token(
            data={"sub": str(user["id"]), "username": user["username"]},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        )
        return {"token": token, "message": "Login successful"}
    except sqlite3.Error:
        # Treat DB errors as authentication failures without exposing details
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid email or password"},
        )
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.post(
    "/set_secret",
    status_code=status.HTTP_200_OK,
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(req: SetSecretRequest, current_user: sqlite3.Row = Depends(get_current_user)):
    """
    Set or update the secret for the authenticated user.
    Enforces authorization: token user must match the provided username (CWE-863).
    Uses parameterized SQL to prevent injection (CWE-89).
    """
    # Authorization check
    if current_user["username"] != req.username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    try:
        conn = get_db()
        with conn:
            # Upsert the secret for the user
            cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (current_user["id"],))
            existing = cur.fetchone()
            now = datetime.utcnow().isoformat()
            if existing is None:
                conn.execute(
                    "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
                    (current_user["id"], req.secret, now),
                )
            else:
                conn.execute(
                    "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
                    (req.secret, now, current_user["id"]),
                )
        return {"message": "Secret has been set successfully"}
    except sqlite3.Error:
        # Handle DB exceptions safely
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "An unexpected error occurred"},
        )
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.get(
    "/get_secret",
    status_code=status.HTTP_200_OK,
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(
    username: str = Query(..., min_length=3, max_length=50, example="user1"),
    current_user: sqlite3.Row = Depends(get_current_user),
):
    """
    Retrieve the secret for the authenticated user.
    Authorization requires username in query to match token user's username (CWE-863).
    """
    if current_user["username"] != username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )

    try:
        conn = get_db()
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (current_user["id"],))
        row = cur.fetchone()
        secret_value = row["secret"] if row is not None else ""
        return {"secret": secret_value}
    except sqlite3.Error:
        # Handle DB exceptions safely
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "An unexpected error occurred"},
        )
    finally:
        try:
            conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    # Start webserver on 0.0.0.0:5000 without streaming responses.
    uvicorn.run(app, host="0.0.0.0", port=5000)