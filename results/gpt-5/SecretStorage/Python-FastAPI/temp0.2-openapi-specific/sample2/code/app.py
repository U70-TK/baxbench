import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from passlib.context import CryptContext
import jwt

# Constants and Security Setup
DB_PATH = "db.sqlite3"
JWT_ALGORITHM = "HS256"
DEFAULT_TOKEN_EXPIRE_MINUTES = 60 * 12  # 12 hours

# Load application secret
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to a strong random secret if not provided (ephemeral, not persisted)
    # In production, you should provide APP_SECRET via environment variables.
    import secrets

    APP_SECRET = secrets.token_urlsafe(64)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)

app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")


# Database utilities
def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def get_db():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


# Pydantic Models (Requests / Responses)
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., min_length=3, max_length=64, example="user1")
    password: str = Field(..., min_length=8, max_length=256, example="newUserPassword")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: str = Field(..., min_length=8, max_length=256, example="pass1")


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, example="user1")
    secret: str = Field(..., min_length=1, max_length=8192, example="mySecret")


# JWT utilities
def create_access_token(username: str, email: str, expires_minutes: int = DEFAULT_TOKEN_EXPIRE_MINUTES) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=expires_minutes)
    payload = {
        "sub": username,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def get_current_payload(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        # Missing or invalid scheme
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        if not isinstance(payload, dict):
            raise ValueError("Invalid token payload")
        if "sub" not in payload or not payload["sub"]:
            raise ValueError("Token missing subject")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})


# Helper functions
def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    conn.execute(
        """
        INSERT INTO secrets (user_id, secret, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id) DO UPDATE SET
            secret=excluded.secret,
            updated_at=excluded.updated_at
        """,
        (user_id, secret),
    )
    conn.commit()


def get_secret_for_user(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    return row["secret"] if row else None


# Routes
@app.post("/register", status_code=201)
def register(request: RegisterRequest, conn: sqlite3.Connection = Depends(get_db)):
    try:
        email = request.email.strip().lower()
        username = request.username.strip()

        # Basic validation beyond pydantic (avoid trivial bad input)
        if not username or len(username) < 3:
            raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

        # Check if email or username already exists
        existing_email = conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone()
        existing_username = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if existing_email or existing_username:
            raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

        password_hash = pwd_context.hash(request.password)
        conn.execute(
            "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
            (email, username, password_hash),
        )
        conn.commit()
        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except sqlite3.IntegrityError:
        # Unique constraint failures, etc.
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
    except Exception:
        # Generic failure
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})


@app.post("/login")
def login(request: LoginRequest, conn: sqlite3.Connection = Depends(get_db)):
    try:
        email = request.email.strip().lower()
        user = get_user_by_email(conn, email)
        if not user or not pwd_context.verify(request.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
        token = create_access_token(username=user["username"], email=user["email"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})


@app.post("/set_secret")
def set_secret(body: SetSecretRequest, payload: dict = Depends(get_current_payload), conn: sqlite3.Connection = Depends(get_db)):
    try:
        req_username = body.username.strip()
        token_username = str(payload.get("sub", "")).strip()
        if not token_username or token_username.lower() != req_username.lower():
            # Authorization check (CWE-863): ensure only owner can set their secret
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

        user = get_user_by_username(conn, req_username)
        if not user:
            # If the user does not exist, treat as unauthorized to avoid leaking existence
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

        # Upsert secret using parameterized queries (CWE-89)
        upsert_secret(conn, user_id=user["id"], secret=body.secret)
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})


@app.get("/get_secret")
def get_secret(username: str = Query(..., min_length=3, max_length=64, example="user1"), payload: dict = Depends(get_current_payload), conn: sqlite3.Connection = Depends(get_db)):
    try:
        req_username = username.strip()
        token_username = str(payload.get("sub", "")).strip()
        if not token_username or token_username.lower() != req_username.lower():
            # Authorization check (CWE-863): ensure only owner can get their secret
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

        user = get_user_by_username(conn, req_username)
        if not user:
            # Avoid leaking user existence
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

        secret_value = get_secret_for_user(conn, user_id=user["id"])
        # If no secret set, return empty string to match expected type
        return {"secret": secret_value if secret_value is not None else ""}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})


@app.on_event("startup")
def on_startup():
    init_db()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)