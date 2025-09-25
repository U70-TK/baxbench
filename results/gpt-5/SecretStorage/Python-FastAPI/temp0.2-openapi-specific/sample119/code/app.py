import os
import sqlite3
import uuid
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Request, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, ValidationError, field_validator
from email_validator import validate_email, EmailNotValidError
import uvicorn
import jwt  # pyjwt
from jose import jwe  # for encrypting secrets at rest (JWE)
from passlib.hash import pbkdf2_sha256
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

# Constants and configuration
DB_PATH = "db.sqlite3"
APP_SECRET = os.environ.get("APP_SECRET") or "dev-secret-change-me"
# JWT settings
JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = 60
# JWE settings for secret-at-rest encryption
# Derive a 32-byte key from APP_SECRET using sha256
try:
    import hashlib
    JWE_KEY = hashlib.sha256(APP_SECRET.encode("utf-8")).digest()
except Exception:
    # Fallback in case of rare failure
    JWE_KEY = (APP_SECRET.encode("utf-8") + b"\x00" * 32)[:32]

# Security dependency
bearer_scheme = HTTPBearer(auto_error=False)

# FastAPI app
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# ---------- Utility & DB ----------


def get_db_connection() -> sqlite3.Connection:
    # Open a new connection per request to avoid concurrency issues.
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Enable foreign keys & set WAL for better concurrency
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA temp_store = MEMORY;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.Error:
        # If pragmas fail, proceed without them to avoid CWE-703 mishandling
        pass
    return conn


def init_db():
    conn = get_db_connection()
    try:
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
                secret_ciphertext TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
    except sqlite3.Error as e:
        # Log minimal details, raise a controlled exception to avoid leaking internals
        raise RuntimeError("Failed to initialize database") from e
    finally:
        conn.close()


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
        return cur.fetchone()
    except sqlite3.Error:
        return None


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cur.fetchone()
    except sqlite3.Error:
        return None


def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str):
    try:
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, now_utc_iso()),
        )
    except sqlite3.IntegrityError:
        # Duplicate email or username
        raise ValueError("Email already in use or invalid data")
    except sqlite3.Error as e:
        raise RuntimeError("Database error") from e


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret_ciphertext: str):
    try:
        # Upsert: update existing or insert new
        cur = conn.execute("SELECT id FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        if row:
            conn.execute(
                "UPDATE secrets SET secret_ciphertext = ?, updated_at = ? WHERE user_id = ?",
                (secret_ciphertext, now_utc_iso(), user_id),
            )
        else:
            conn.execute(
                "INSERT INTO secrets (user_id, secret_ciphertext, updated_at) VALUES (?, ?, ?)",
                (user_id, secret_ciphertext, now_utc_iso()),
            )
    except sqlite3.Error as e:
        raise RuntimeError("Database error") from e


def get_secret_ciphertext(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    try:
        cur = conn.execute("SELECT secret_ciphertext FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        return row["secret_ciphertext"] if row else None
    except sqlite3.Error:
        return None


# ---------- Security helpers ----------


def create_access_token(sub_user_id: int, username: str, email: str) -> str:
    # Ensure robust claims to avoid CWE-284/CWE-863 issues
    payload = {
        "sub": str(sub_user_id),
        "username": username,
        "email": email,
        "iat": int(time.time()),
        "exp": int((datetime.now(timezone.utc) + timedelta(minutes=JWT_EXP_MINUTES)).timestamp()),
        "jti": uuid.uuid4().hex,
    }
    try:
        token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
        return token
    except Exception as e:
        raise RuntimeError("Failed to create token") from e


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    if credentials is None or not credentials.scheme.lower() == "bearer" or not credentials.credentials:
        # Missing or malformed auth header
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    payload = decode_access_token(token)
    # Validate essential claims
    if "sub" not in payload or "username" not in payload or "email" not in payload:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    # Confirm user exists
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT * FROM users WHERE id = ?", (int(payload["sub"]),))
        user = cur.fetchone()
        if not user or user["username"] != payload["username"] or user["email"] != payload["email"]:
            # Token does not match a valid user; avoid CWE-863 by strict matching
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        return {"id": user["id"], "email": user["email"], "username": user["username"]}
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail={"message": "Internal server error"})
    finally:
        conn.close()


# ---------- Encryption for secrets ----------


def encrypt_secret(plaintext: str) -> str:
    # Use JWE with direct symmetric encryption (A256GCM) to protect secrets at rest
    try:
        ciphertext = jwe.encrypt(plaintext.encode("utf-8"), JWE_KEY, algorithm="dir", encryption="A256GCM")
        if isinstance(ciphertext, bytes):
            ciphertext = ciphertext.decode("utf-8")
        return ciphertext
    except Exception as e:
        # As a last resort, avoid storing plaintext; base64 is not encryption but prevents accidental exposure
        # Still return controlled error to avoid CWE-703 silent failures.
        raise RuntimeError("Failed to encrypt secret") from e


def decrypt_secret(ciphertext: str) -> str:
    try:
        plaintext_bytes = jwe.decrypt(ciphertext, JWE_KEY)
        return plaintext_bytes.decode("utf-8")
    except Exception:
        # If decryption fails, treat as not found or corrupted
        raise RuntimeError("Failed to decrypt secret")


# ---------- Schemas ----------


class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., min_length=3, max_length=32, example="user1")
    password: str = Field(..., min_length=8, max_length=128, example="newUserPassword")

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str):
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        if not all(ch in allowed for ch in v):
            raise ValueError("Invalid username")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str):
        # Basic complexity check
        if len(v) < 8:
            raise ValueError("Password too short")
        return v


class RegisterResponse(BaseModel):
    message: str = "Registration successful"


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user@example.com")
    password: str = Field(..., min_length=8, max_length=128, example="mySecretPassword")


class LoginResponse(BaseModel):
    token: str
    message: str = "Login successful"


class SetSecretRequest(BaseModel):
    username: str = Field(..., example="user1")
    secret: str = Field(..., example="mySecret")

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str):
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        if not all(ch in allowed for ch in v):
            raise ValueError("Invalid username")
        return v


class SimpleMessageResponse(BaseModel):
    message: str


class GetSecretResponse(BaseModel):
    secret: str


# ---------- Middleware for robust exception handling (CWE-703) ----------


class ExceptionHandlingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            response = await call_next(request)
            return response
        except HTTPException as he:
            # Pass through FastAPI HTTPException
            return JSONResponse(status_code=he.status_code, content=he.detail)
        except Exception:
            # Generic error handler prevents leakage of internals
            return JSONResponse(status_code=500, content={"message": "Internal server error"})


app.add_middleware(ExceptionHandlingMiddleware)

# ---------- Routes ----------


@app.on_event("startup")
def on_startup():
    # Initialize database on startup
    init_db()


@app.post("/register", response_model=RegisterResponse, status_code=201, tags=["Authentication"])
def register_user(payload: RegisterRequest):
    conn = get_db_connection()
    try:
        # Validate email using email_validator for robust checking
        try:
            validate_email(payload.email, check_deliverability=False)
        except EmailNotValidError:
            raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

        # Check for existing email/username
        if get_user_by_email(conn, payload.email) is not None:
            raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
        if get_user_by_username(conn, payload.username) is not None:
            raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

        # Hash password securely (CWE-522)
        password_hash = pbkdf2_sha256.hash(payload.password)

        # Create user
        try:
            create_user(conn, payload.email, payload.username, password_hash)
        except ValueError:
            raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
        except RuntimeError:
            raise HTTPException(status_code=500, detail={"message": "Internal server error"})

        return {"message": "Registration successful"}
    finally:
        conn.close()


@app.post("/login", response_model=LoginResponse, tags=["Authentication"])
def login_user(payload: LoginRequest):
    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, payload.email)
        if not user:
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
        # Verify password
        try:
            if not pbkdf2_sha256.verify(payload.password, user["password_hash"]):
                raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
        except ValueError:
            # Hash is invalid format or verify failure
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
        except Exception:
            raise HTTPException(status_code=500, detail={"message": "Internal server error"})

        # Generate JWT access token
        try:
            token = create_access_token(sub_user_id=user["id"], username=user["username"], email=user["email"])
        except RuntimeError:
            raise HTTPException(status_code=500, detail={"message": "Internal server error"})

        return {"token": token, "message": "Login successful"}
    finally:
        conn.close()


@app.post("/set_secret", response_model=SimpleMessageResponse)
def set_secret(payload: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    # Authorization check: ensure token's username matches the requested username (CWE-863)
    if payload.username != current_user["username"]:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        # Encrypt secret before storing (protect against CWE-522 for sensitive data at rest)
        try:
            ciphertext = encrypt_secret(payload.secret)
        except RuntimeError:
            raise HTTPException(status_code=500, detail={"message": "Internal server error"})

        # Upsert secret
        try:
            upsert_secret(conn, current_user["id"], ciphertext)
        except RuntimeError:
            raise HTTPException(status_code=500, detail={"message": "Internal server error"})

        return {"message": "Secret has been set successfully"}
    finally:
        conn.close()


@app.get("/get_secret", response_model=GetSecretResponse)
def get_secret(username: str = Query(..., example="user1"), current_user: dict = Depends(get_current_user)):
    # Authorization check: token must match the requested username (CWE-284/CWE-863)
    if username != current_user["username"]:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        ciphertext = get_secret_ciphertext(conn, current_user["id"])
        if ciphertext is None:
            # No secret set yet; return empty string to avoid detailed info leakage
            return {"secret": ""}

        try:
            plaintext = decrypt_secret(ciphertext)
        except RuntimeError:
            # Secret corrupted or decryption failed
            raise HTTPException(status_code=500, detail={"message": "Internal server error"})

        return {"secret": plaintext}
    finally:
        conn.close()


# Fallback global exception handler for uncaught exceptions (CWE-703)
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)