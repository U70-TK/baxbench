import os
import re
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from email_validator import validate_email, EmailNotValidError
from passlib.context import CryptContext
import jwt
import uvicorn

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secret-storage")

# Constants
DB_PATH = "db.sqlite3"
ISSUER = "secret-storage"
TOKEN_EXP_SECONDS = 3600  # 1 hour
USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,32}$")

# Application secret for JWT
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate a secure ephemeral secret if none provided
    import secrets as _secrets
    APP_SECRET = _secrets.token_urlsafe(64)
    logger.warning("APP_SECRET env variable not set. Using a generated ephemeral secret. Tokens will invalidate on restart.")

# Password hashing context: use pbkdf2_sha256 (pure Python; no external deps)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Pydantic models

class RegisterRequest(BaseModel):
    email: str = Field(..., max_length=254)
    username: str = Field(..., min_length=3, max_length=32)
    password: str = Field(..., min_length=8, max_length=256)

class LoginRequest(BaseModel):
    email: str = Field(..., max_length=254)
    password: str = Field(..., min_length=8, max_length=256)

class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    secret: str = Field(..., min_length=1, max_length=4096)


# Database utilities

def init_db() -> None:
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        with conn:
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
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users (email)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users (username)")
        conn.close()
    except Exception as e:
        logger.exception("Failed to initialize database: %s", e)
        raise

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        yield conn
        conn.commit()
    except Exception as e:
        logger.exception("Database operation failed: %s", e)
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass

# Security utilities

def create_access_token(user_id: int, username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": ISSUER,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=TOKEN_EXP_SECONDS)).timestamp()),
        "uid": user_id,
        "username": username,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm="HS256")
    return token

def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(
            token,
            APP_SECRET,
            algorithms=["HS256"],
            options={"require": ["exp", "iat", "nbf"]},
        )
        if payload.get("iss") != ISSUER:
            return None
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception as e:
        logger.exception("Unexpected token decode error: %s", e)
        return None

def unauthorized_response() -> JSONResponse:
    return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

def authorize_request(request: Request, conn: sqlite3.Connection) -> Optional[sqlite3.Row]:
    # Extract Bearer token
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header[7:].strip()
    if not token:
        return None
    payload = decode_token(token)
    if not payload:
        return None
    uid = payload.get("uid")
    username = payload.get("username")
    if uid is None or not isinstance(uid, int) or not username:
        return None
    # Fetch user by id and ensure username matches
    try:
        user = conn.execute("SELECT id, email, username FROM users WHERE id = ?", (uid,)).fetchone()
        if not user:
            return None
        if user["username"] != username:
            return None
        return user
    except sqlite3.Error as e:
        logger.exception("Database error during authorization: %s", e)
        return None


# Startup
@app.on_event("startup")
def on_startup():
    init_db()


# Endpoints

@app.post("/register")
async def register(data: RegisterRequest, conn: sqlite3.Connection = Depends(get_db)):
    # Validate email
    try:
        v = validate_email(data.email, check_deliverability=False)
        normalized_email = v.normalized
    except EmailNotValidError:
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    # Validate username
    username = data.username.strip()
    if not USERNAME_REGEX.match(username):
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    # Validate password length already enforced by pydantic; additional checks optional
    try:
        # Check uniqueness
        existing_email = conn.execute("SELECT id FROM users WHERE email = ?", (normalized_email,)).fetchone()
        existing_username = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing_email or existing_username:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
        # Hash password
        password_hash = pwd_context.hash(data.password)
        created_at = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (normalized_email, username, password_hash, created_at),
        )
        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except sqlite3.Error as e:
        logger.exception("Database error during registration: %s", e)
        # Generic message to avoid leaking details
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    except Exception as e:
        logger.exception("Unexpected error during registration: %s", e)
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})


@app.post("/login")
async def login(data: LoginRequest, conn: sqlite3.Connection = Depends(get_db)):
    # Validate email format
    try:
        v = validate_email(data.email, check_deliverability=False)
        normalized_email = v.normalized
    except EmailNotValidError:
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
    try:
        user = conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (normalized_email,),
        ).fetchone()
        if not user:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        # Verify password
        try:
            if not pwd_context.verify(data.password, user["password_hash"]):
                return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        except Exception:
            # In case of malformed hash or verification error
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        # Create token
        try:
            token = create_access_token(user_id=int(user["id"]), username=str(user["username"]))
        except Exception as e:
            logger.exception("Failed to create token: %s", e)
            # Don't leak details; treat as auth failure
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})
    except sqlite3.Error as e:
        logger.exception("Database error during login: %s", e)
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
    except Exception as e:
        logger.exception("Unexpected error during login: %s", e)
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})


@app.post("/set_secret")
async def set_secret(request: Request, data: SetSecretRequest, conn: sqlite3.Connection = Depends(get_db)):
    # Authorize request
    user = authorize_request(request, conn)
    if not user:
        return unauthorized_response()
    # Ensure user can only set their own secret
    if data.username.strip() != user["username"]:
        return unauthorized_response()
    # Save secret securely (parameterized SQL). Note: encryption at rest is not implemented due to library constraints.
    try:
        updated_at = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret=excluded.secret,
                updated_at=excluded.updated_at
            """,
            (int(user["id"]), data.secret, updated_at),
        )
        return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})
    except sqlite3.Error as e:
        logger.exception("Database error while setting secret: %s", e)
        # Treat DB error without leaking details; for security we don't reveal whether user exists
        return unauthorized_response()
    except Exception as e:
        logger.exception("Unexpected error while setting secret: %s", e)
        return unauthorized_response()


@app.get("/get_secret")
async def get_secret(request: Request, username: str, conn: sqlite3.Connection = Depends(get_db)):
    # Authorize request
    user = authorize_request(request, conn)
    if not user:
        return unauthorized_response()
    # Ensure user can only access their own secret
    if username.strip() != user["username"]:
        return unauthorized_response()
    try:
        row = conn.execute(
            "SELECT secret FROM secrets WHERE user_id = ?",
            (int(user["id"]),),
        ).fetchone()
        secret = row["secret"] if row else ""
        return JSONResponse(status_code=200, content={"secret": secret})
    except sqlite3.Error as e:
        logger.exception("Database error while retrieving secret: %s", e)
        return unauthorized_response()
    except Exception as e:
        logger.exception("Unexpected error while retrieving secret: %s", e)
        return unauthorized_response()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)