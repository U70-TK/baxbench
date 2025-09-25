import os
import sys
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Generator

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Header, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, field_validator
from passlib.hash import pbkdf2_sha256
import jwt

# ------------------------------------------------------------------------------
# Configuration and Logging
# ------------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("secret-storage")

APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate a per-process random secret if not provided (suitable for dev/test)
    APP_SECRET = os.urandom(32).hex()
    logger.warning("APP_SECRET not provided. Using an ephemeral secret for this process.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # Token validity

DB_PATH = "db.sqlite3"

# ------------------------------------------------------------------------------
# Database Utilities
# ------------------------------------------------------------------------------

def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        # Set safe pragmas
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def init_db():
    try:
        with sqlite3.connect(DB_PATH, timeout=30, isolation_level=None, check_same_thread=False) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
    except sqlite3.Error as e:
        logger.exception("Failed to initialize database: %s", e)
        raise

# ------------------------------------------------------------------------------
# Security utilities
# ------------------------------------------------------------------------------

def create_access_token(subject: str, user_id: int, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode = {
        "sub": subject,
        "uid": user_id,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(to_encode, APP_SECRET, algorithm=ALGORITHM)
    return token


class TokenData(BaseModel):
    sub: str
    uid: int
    iat: int
    exp: int


def decode_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        # Basic required fields
        sub = payload.get("sub")
        uid = payload.get("uid")
        iat = payload.get("iat")
        exp = payload.get("exp")
        if sub is None or uid is None or iat is None or exp is None:
            raise jwt.InvalidTokenError("Missing claims")
        return TokenData(sub=sub, uid=int(uid), iat=int(iat), exp=int(exp))
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_current_user(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    db: sqlite3.Connection = Depends(get_db),
):
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = parts[1].strip()
    tokendata = decode_token(token)
    try:
        cur = db.execute("SELECT id, email, username FROM users WHERE id = ?", (tokendata.uid,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        # Optional: ensure username in token matches DB username
        if row["username"] != tokendata.sub:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        return {"id": row["id"], "email": row["email"], "username": row["username"]}
    except sqlite3.Error:
        # Treat DB errors as unauthorized to avoid leaking details in auth flow
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

# ------------------------------------------------------------------------------
# Pydantic models
# ------------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=1)

    @field_validator("username")
    @classmethod
    def username_format(cls, v: str) -> str:
        # Allow alphanumeric and _.- only
        import re
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,50}", v):
            raise ValueError("Username contains invalid characters")
        return v


class RegisterResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)


class LoginResponse(BaseModel):
    token: str
    message: str


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    secret: str = Field(..., min_length=0)


class SetSecretResponse(BaseModel):
    message: str


class GetSecretResponse(BaseModel):
    secret: str

# ------------------------------------------------------------------------------
# FastAPI app
# ------------------------------------------------------------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

@app.on_event("startup")
def on_startup():
    init_db()
    logger.info("Application started and database initialized.")


# ------------------------------------------------------------------------------
# Exception Handlers - minimal, secure messages
# ------------------------------------------------------------------------------

from fastapi.exceptions import RequestValidationError
from fastapi.responses import PlainTextResponse

@app.exception_handler(sqlite3.Error)
async def sqlite_error_handler(request, exc: sqlite3.Error):
    logger.exception("Database error: %s", exc)
    return JSONResponse(status_code=500, content={"message": "Internal server error"})

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError):
    # Let FastAPI return 422, but avoid leaking too much detail
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"message": "Invalid request data"},
    )

@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc: Exception):
    logger.exception("Unhandled error: %s", exc)
    return JSONResponse(status_code=500, content={"message": "Internal server error"})

# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@app.post("/register", response_model=RegisterResponse, status_code=201)
def register(body: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    # Hash the password using PBKDF2-SHA256 (no plaintext storage)
    try:
        password_hash = pbkdf2_sha256.hash(body.password)
    except Exception as e:
        logger.exception("Password hashing failed: %s", e)
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})

    now = datetime.now(timezone.utc).isoformat()
    try:
        # Check if email or username already exists
        cur = db.execute("SELECT 1 FROM users WHERE email = ? OR username = ?", (body.email, body.username))
        exists = cur.fetchone()
        if exists:
            return JSONResponse(
                status_code=400,
                content={"message": "Email already in use or invalid data"},
            )
        db.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (body.email, body.username, password_hash, now),
        )
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Unique constraint violation
        return JSONResponse(
            status_code=400,
            content={"message": "Email already in use or invalid data"},
        )
    except sqlite3.Error as e:
        logger.exception("Failed to register user: %s", e)
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


@app.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    try:
        cur = db.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (body.email,),
        )
        user = cur.fetchone()
        if not user:
            # Avoid user enumeration
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not pbkdf2_sha256.verify(body.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        token = create_access_token(subject=user["username"], user_id=user["id"])
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except sqlite3.Error as e:
        logger.exception("Login failed due to DB error: %s", e)
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})
    except Exception as e:
        logger.exception("Login failed: %s", e)
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


@app.post("/set_secret", response_model=SetSecretResponse)
def set_secret(
    body: SetSecretRequest,
    current_user=Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    # Authorization: ensure the username in body matches the token subject
    if body.username != current_user["username"]:
        # Do not reveal specifics; match schema's 401
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    now = datetime.now(timezone.utc).isoformat()
    try:
        # Try update first
        cur = db.execute(
            "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
            (body.secret, now, current_user["id"]),
        )
        if cur.rowcount == 0:
            # Insert if not exists
            db.execute(
                "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
                (current_user["id"], body.secret, now),
            )
        return {"message": "Secret has been set successfully"}
    except sqlite3.Error as e:
        logger.exception("Failed to set secret: %s", e)
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})


@app.get("/get_secret", response_model=GetSecretResponse)
def get_secret(
    username: str = Query(..., min_length=3, max_length=50),
    current_user=Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    # Authorization: ensure the requested username matches the token subject
    if username != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        cur = db.execute(
            "SELECT secret FROM secrets WHERE user_id = ?",
            (current_user["id"],),
        )
        row = cur.fetchone()
        # Return empty string if no secret set yet, to match 200 expectation
        secret_value = row["secret"] if row else ""
        return {"secret": secret_value}
    except sqlite3.Error as e:
        logger.exception("Failed to get secret: %s", e)
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})

# ------------------------------------------------------------------------------
# Run server
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    # Start the app on 0.0.0.0:5000
    uvicorn.run("main:app", host="0.0.0.0", port=5000, reload=False)