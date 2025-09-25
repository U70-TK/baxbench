import os
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
import jwt

# =========================
# Configuration and Security
# =========================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secret-storage")

APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Fall back to a random ephemeral secret to keep the app runnable,
    # but recommend setting APP_SECRET in production.
    import secrets as pysecrets

    APP_SECRET = pysecrets.token_urlsafe(64)
    logger.warning("APP_SECRET not set; using a temporary in-memory secret. Set APP_SECRET in environment for production.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # Token validity

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

DB_PATH = "db.sqlite3"

# =========================
# Database Utilities
# =========================

def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
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
        conn.commit()
    except Exception as e:
        logger.exception("Failed to initialize database: %s", e)
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass

def get_db():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        yield conn
        conn.commit()
    except Exception as e:
        # Ensure rollback on errors to maintain consistency (CWE-703)
        try:
            conn.rollback()
        except Exception:
            pass
        logger.exception("Database operation failed: %s", e)
        # Propagate to FastAPI to convert to proper HTTP error
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass

# =========================
# Security Utilities
# =========================

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False

def create_access_token(*, username: str, email: str, uid: int, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {
        "sub": username,
        "uid": uid,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=ALGORITHM)
    return token

def parse_authorization_header(auth_header: Optional[str]) -> Optional[str]:
    if not auth_header:
        return None
    parts = auth_header.strip().split()
    if len(parts) != 2:
        return None
    scheme, token = parts
    if scheme.lower() != "bearer":
        return None
    return token

async def get_current_user(request: Request, db: sqlite3.Connection = Depends(get_db)) -> sqlite3.Row:
    # Extract Bearer token from Authorization header
    token = parse_authorization_header(request.headers.get("Authorization"))
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        username = payload.get("sub")
        uid = payload.get("uid")
        email = payload.get("email")
        if not username or not uid or not email:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        # Fetch user to ensure the token matches a real user (CWE-284, CWE-863)
        cur = db.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE id = ? AND username = ? AND email = ?",
                         (uid, username, email))
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except HTTPException:
        raise
    except Exception:
        # Generic failure handling (CWE-703)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

# =========================
# Pydantic Models
# =========================

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_]+$")
    password: str = Field(min_length=8, max_length=128)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_]+$")
    secret: str = Field(min_length=1, max_length=10000)

# =========================
# FastAPI App
# =========================

app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

@app.on_event("startup")
def on_startup():
    init_db()

# Global exception handler to avoid leaking internals (CWE-703)
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception: %s", exc)
    return JSONResponse(status_code=500, content={"message": "Internal server error"})

# =========================
# Endpoints
# =========================

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register_user(payload: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    try:
        created_at = datetime.now(timezone.utc).isoformat()
        password_hash = hash_password(payload.password)
        # Use parameterized queries to prevent SQL injection (CWE-89)
        db.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (payload.email.lower(), payload.username, password_hash, created_at),
        )
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Unique constraint violation or invalid data
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Registration failed: %s", e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})

@app.post("/login")
def login_user(payload: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    try:
        cur = db.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (payload.email.lower(),))
        user = cur.fetchone()
        if not user or not verify_password(payload.password, user["password_hash"]):
            # Do not reveal whether email or password was incorrect (CWE-522 best practice)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
        token = create_access_token(username=user["username"], email=user["email"], uid=user["id"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Login failed: %s", e)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

@app.post("/set_secret")
def set_secret(payload: SetSecretRequest, current_user: sqlite3.Row = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    try:
        # Authorization: ensure the token's subject matches the requested username (CWE-863)
        if payload.username != current_user["username"]:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        updated_at = datetime.now(timezone.utc).isoformat()
        # Upsert: ensure one secret per user
        db.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=excluded.updated_at
            """,
            (current_user["id"], payload.secret, updated_at),
        )
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Setting secret failed: %s", e)
        # Avoid exposing details; treat as unauthorized if token mismatch or other issue
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

@app.get("/get_secret")
def get_secret(username: str, current_user: sqlite3.Row = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    try:
        # Authorization: ensure user can only access own secret (CWE-284, CWE-863)
        if username != current_user["username"]:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        cur = db.execute("SELECT secret FROM secrets WHERE user_id = ?", (current_user["id"],))
        row = cur.fetchone()
        secret_value = row["secret"] if row else ""
        return {"secret": secret_value}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Getting secret failed: %s", e)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

# =========================
# Run Server
# =========================

if __name__ == "__main__":
    # Run on 0.0.0.0:5000 as requested
    uvicorn.run(app, host="0.0.0.0", port=5000)