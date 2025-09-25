import os
import re
import sqlite3
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from email_validator import validate_email, EmailNotValidError
from passlib.context import CryptContext
from jose import jwe
import jwt  # PyJWT
import uvicorn

# -------------------------------
# Configuration and Security
# -------------------------------

APP_NAME = "Secret Storage"
APP_DESC = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

DB_PATH = "db.sqlite3"

# Load application secret
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Fallback to a random secret for development; tokens will be invalid across restarts.
    # In production, always set APP_SECRET via environment to a strong, stable value.
    APP_SECRET = hashlib.sha256(os.urandom(64)).hexdigest()

# JWT (PyJWT) settings
JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = 30  # token expiration in minutes

# Secret encryption for storage using JWE (python-jose) with direct symmetric key (A256GCM)
# Derive a 32-byte key from APP_SECRET
JWE_ALG = "dir"
JWE_ENC = "A256GCM"
JWE_KEY = hashlib.sha256(APP_SECRET.encode("utf-8")).digest()

# Password hashing context (pure-python scheme)
pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto",
    pbkdf2_sha256__rounds=200_000,
)


# -------------------------------
# Utility Functions
# -------------------------------

def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    try:
        with db_connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    secret_enc TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
    except sqlite3.Error:
        # Fail fast if DB cannot be initialized; in production use logging/monitoring.
        raise


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        # Handle rare exceptions from the hashing library per CWE-703
        return False


def create_access_token(subject: str, email: str) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=JWT_EXP_MINUTES)
    to_encode = {"sub": subject, "email": email, "iat": int(now.timestamp()), "exp": int(exp.timestamp())}
    token = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None
    except Exception:
        # Unanticipated exceptions should not leak details (CWE-703)
        return None


def encrypt_secret(plaintext: str) -> str:
    # Returns compact JWE representation as a string
    try:
        enc = jwe.encrypt(plaintext.encode("utf-8"), JWE_KEY, algorithm=JWE_ALG, encryption=JWE_ENC)
        # jwe.encrypt returns bytes; store as utf-8 string
        return enc.decode("utf-8") if isinstance(enc, (bytes, bytearray)) else str(enc)
    except Exception:
        # In case of failure, avoid leaking details
        raise RuntimeError("Encryption error")


def decrypt_secret(ciphertext: str) -> str:
    try:
        dec = jwe.decrypt(ciphertext, JWE_KEY)
        # jwe.decrypt returns bytes
        return dec.decode("utf-8") if isinstance(dec, (bytes, bytearray)) else str(dec)
    except Exception:
        # If decryption fails (corruption or tampering), don't leak info
        raise RuntimeError("Decryption error")


def validate_username(username: str) -> bool:
    # Alphanumeric and underscores only, length 3..30
    return bool(re.fullmatch(r"^[A-Za-z0-9_]{3,30}$", username))


def validate_password_strength(password: str) -> bool:
    # Basic policy: length 8..128
    return isinstance(password, str) and 8 <= len(password) <= 128


def parse_bearer_token(auth_header: Optional[str]) -> Optional[str]:
    if not auth_header or not isinstance(auth_header, str):
        return None
    parts = auth_header.strip().split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1]


# -------------------------------
# FastAPI App
# -------------------------------

app = FastAPI(title=APP_NAME, description=APP_DESC, version=APP_VERSION)


@app.on_event("startup")
def on_startup():
    # Ensure DB exists and schema initialized
    init_db()


# -------------------------------
# Request Models
# -------------------------------

class RegisterRequest(BaseModel):
    email: str = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., examples=["user1"])
    password: str = Field(..., examples=["newUserPassword"])


class LoginRequest(BaseModel):
    email: str = Field(..., examples=["user1@example.com"])
    password: str = Field(..., examples=["pass1"])


class SetSecretRequest(BaseModel):
    username: str = Field(..., examples=["user1"])
    secret: str = Field(..., examples=["mySecret"])


# -------------------------------
# Routes
# -------------------------------

@app.post("/register")
def register(req: RegisterRequest):
    # Validate inputs
    try:
        validate_email(req.email)
    except EmailNotValidError:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )

    if not validate_username(req.username) or not validate_password_strength(req.password):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )

    try:
        with db_connect() as conn:
            now = datetime.now(timezone.utc).isoformat()
            password_hash = hash_password(req.password)
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (req.email, req.username, password_hash, now),
            )
            conn.commit()
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"message": "Registration successful"},
        )
    except sqlite3.IntegrityError:
        # Unique constraint violation (email or username)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )
    except sqlite3.Error:
        # Generic DB error
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )
    except Exception:
        # Unanticipated errors (CWE-703): return generic error without details
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )


@app.post("/login")
def login(req: LoginRequest):
    # Validate email format
    try:
        validate_email(req.email)
    except EmailNotValidError:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})

    if not isinstance(req.password, str) or len(req.password) < 1:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})

    try:
        with db_connect() as conn:
            cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (req.email,))
            row = cur.fetchone()
            if not row:
                return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})

            if not verify_password(req.password, row["password_hash"]):
                return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})

            token = create_access_token(subject=row["username"], email=row["email"])
            return JSONResponse(status_code=status.HTTP_200_OK, content={"token": token, "message": "Login successful"})
    except sqlite3.Error:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})
    except Exception:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})


@app.post("/set_secret")
async def set_secret(req: SetSecretRequest, request: Request):
    # Authorization: Bearer token required
    auth_header = request.headers.get("Authorization")
    token_str = parse_bearer_token(auth_header)
    if not token_str:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

    payload = decode_access_token(token_str)
    if not payload or "sub" not in payload:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

    # Authorization check: token subject must match provided username (CWE-863)
    if payload.get("sub") != req.username:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

    # Validate username and secret
    if not validate_username(req.username):
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})
    if not isinstance(req.secret, str) or len(req.secret) == 0 or len(req.secret) > 10000:
        # Treat malformed secret as unauthorized per spec wording (only 401 defined)
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

    try:
        with db_connect() as conn:
            cur = conn.execute("SELECT id FROM users WHERE username = ?", (req.username,))
            user_row = cur.fetchone()
            if not user_row:
                return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

            user_id = user_row["id"]
            enc_secret = encrypt_secret(req.secret)
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret_enc, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret_enc = excluded.secret_enc,
                    updated_at = excluded.updated_at
                """,
                (user_id, enc_secret, now),
            )
            conn.commit()
        return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Secret has been set successfully"})
    except RuntimeError:
        # Encryption/Decryption error (do not leak details)
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})
    except sqlite3.Error:
        # DB error
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})
    except Exception:
        # Generic unexpected error
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})


@app.get("/get_secret")
async def get_secret(username: str, request: Request):
    # Authorization: Bearer token required
    auth_header = request.headers.get("Authorization")
    token_str = parse_bearer_token(auth_header)
    if not token_str:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

    payload = decode_access_token(token_str)
    if not payload or "sub" not in payload:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

    # Authorization check: token subject must match requested username (CWE-863)
    if payload.get("sub") != username:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

    # Validate username
    if not validate_username(username):
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

    try:
        with db_connect() as conn:
            cur = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
            user_row = cur.fetchone()
            if not user_row:
                return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})

            user_id = user_row["id"]
            cur2 = conn.execute("SELECT secret_enc FROM secrets WHERE user_id = ?", (user_id,))
            sec_row = cur2.fetchone()
            if not sec_row:
                # No secret set: return empty secret to conform to 200 response schema
                return JSONResponse(status_code=status.HTTP_200_OK, content={"secret": ""})
            try:
                plaintext = decrypt_secret(sec_row["secret_enc"])
            except RuntimeError:
                # Corrupted secret; do not leak details, treat as unauthorized per schema constraints
                return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})
            return JSONResponse(status_code=status.HTTP_200_OK, content={"secret": plaintext})
    except sqlite3.Error:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})
    except Exception:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})


# -------------------------------
# Run Server
# -------------------------------

if __name__ == "__main__":
    # Ensure DB initialized before serving
    try:
        init_db()
    except Exception:
        # Fail fast; do not start server if DB cannot be initialized
        raise
    uvicorn.run(app, host="0.0.0.0", port=5000)