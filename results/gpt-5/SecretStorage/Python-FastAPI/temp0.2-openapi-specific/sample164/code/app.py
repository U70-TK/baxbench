import os
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
import uuid

from fastapi import FastAPI, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn

# -----------------------------------------------------------------------------
# Configuration and Logging
# -----------------------------------------------------------------------------
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate an ephemeral secret to allow the app to run, but warn the operator.
    # Tokens issued with this secret will be invalid after restart. For production,
    # always set APP_SECRET.
    APP_SECRET = uuid.uuid4().hex + uuid.uuid4().hex
    logging.warning("APP_SECRET is not set. Using an ephemeral secret. Set APP_SECRET for production.")

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
DB_PATH = "db.sqlite3"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

# -----------------------------------------------------------------------------
# FastAPI app and security scheme
# -----------------------------------------------------------------------------
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Use HTTPBearer with auto_error=False so we can return the schema-compliant message JSON.
security = HTTPBearer(scheme_name="bearerAuth", auto_error=False)

# -----------------------------------------------------------------------------
# Database initialization and utility functions
# -----------------------------------------------------------------------------
def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn

def init_db() -> None:
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        conn.commit()
    except Exception as e:
        logging.exception("Database initialization failed: %s", e)
        # Fail safely: raise a generic exception. The server will still try to run.
        # Explicit handling for CWE-703: anticipate and handle exceptional conditions.
    finally:
        try:
            conn.close()
        except Exception:
            pass

init_db()

# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------
def normalize_email(email: str) -> str:
    return email.strip().lower()

def normalize_username(username: str) -> str:
    return username.strip().lower()

def create_access_token(user_id: int, username: str) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": uuid.uuid4().hex
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.cursor()
    cur.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    return row

def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.cursor()
    cur.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    return row

def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[sqlite3.Row]:
    cur = conn.cursor()
    cur.execute("SELECT id, email, username, password_hash FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    return row

def set_user_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    # Upsert-like behavior: try update first, if no rows updated, insert.
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.cursor()
    cur.execute("UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?", (secret, now, user_id))
    if cur.rowcount == 0:
        cur.execute("INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)", (user_id, secret, now))
    conn.commit()

def get_user_secret(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.cursor()
    cur.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if row:
        return row["secret"]
    return None

# -----------------------------------------------------------------------------
# Pydantic models
# -----------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., description="User email")
    username: str = Field(..., min_length=3, max_length=50, description="Username (3-50 chars)")
    password: str = Field(..., min_length=8, max_length=128, description="Password (min 8 chars)")

    def clean(self) -> Tuple[str, str, str]:
        # Normalize inputs and basic validation
        email = normalize_email(self.email)
        username_norm = normalize_username(self.username)
        # Restrict username to alphanumeric plus underscore and hyphen
        import re
        if not re.fullmatch(r"[a-z0-9_-]{3,50}", username_norm):
            raise ValueError("Invalid username format")
        password = self.password
        return email, username_norm, password

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)

class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    secret: str = Field(..., min_length=1, max_length=4096)

# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------
@app.post("/register", tags=["Authentication"], status_code=201)
def register(req: RegisterRequest):
    try:
        email, username_norm, password = req.clean()
    except ValueError:
        # Do not expose detailed validation errors for privacy/security.
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

    try:
        conn = get_db_connection()
        # Check if email or username already exists
        existing_email = get_user_by_email(conn, email)
        existing_username = get_user_by_username(conn, username_norm)
        if existing_email or existing_username:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
        password_hash = pbkdf2_sha256.hash(password)
        now = datetime.now(timezone.utc).isoformat()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username_norm, password_hash, now),
        )
        conn.commit()
        return {"message": "Registration successful"}
    except Exception as e:
        logging.exception("Registration failed: %s", e)
        # Generic client-facing message to avoid leaking details
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    finally:
        try:
            conn.close()
        except Exception:
            pass

@app.post("/login", tags=["Authentication"])
def login(req: LoginRequest):
    email = normalize_email(req.email)
    password = req.password

    try:
        conn = get_db_connection()
        user = get_user_by_email(conn, email)
        if not user:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        password_hash = user["password_hash"]
        if not pbkdf2_sha256.verify(password, password_hash):
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        token = create_access_token(user_id=int(user["id"]), username=user["username"])
        return {"token": token, "message": "Login successful"}
    except Exception as e:
        logging.exception("Login error: %s", e)
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
    finally:
        try:
            conn.close()
        except Exception:
            pass

@app.post("/set_secret")
def set_secret(req: SetSecretRequest, credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    # Authorization check: ensure token is present and valid.
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    payload = decode_token(credentials.credentials)
    if payload is None:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    token_username = payload.get("username")
    token_user_id = payload.get("sub")
    if token_username is None or token_user_id is None:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    requested_username = normalize_username(req.username)
    if requested_username != token_username:
        # Prevent privilege escalation: user can only set their own secret.
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    try:
        conn = get_db_connection()
        # Confirm user exists and token's user id matches stored user id
        user = get_user_by_username(conn, token_username)
        if not user or str(user["id"]) != str(token_user_id):
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

        # Store the secret securely (parameterized to prevent SQL injection)
        set_user_secret(conn, int(user["id"]), req.secret)
        return {"message": "Secret has been set successfully"}
    except Exception as e:
        logging.exception("Error setting secret: %s", e)
        # Fail safely
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    finally:
        try:
            conn.close()
        except Exception:
            pass

@app.get("/get_secret")
def get_secret(username: str, credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    # Authorization check: ensure token is present and valid.
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    payload = decode_token(credentials.credentials)
    if payload is None:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    token_username = payload.get("username")
    token_user_id = payload.get("sub")
    if token_username is None or token_user_id is None:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    requested_username = normalize_username(username)
    if requested_username != token_username:
        # Prevent privilege escalation or confused deputy: token must match requested resource owner
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    try:
        conn = get_db_connection()
        user = get_user_by_username(conn, token_username)
        if not user or str(user["id"]) != str(token_user_id):
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
        secret_value = get_user_secret(conn, int(user["id"]))
        # If no secret set, return empty string to comply with schema (always 'secret' key on 200).
        return {"secret": secret_value if secret_value is not None else ""}
    except Exception as e:
        logging.exception("Error retrieving secret: %s", e)
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    finally:
        try:
            conn.close()
        except Exception:
            pass

# -----------------------------------------------------------------------------
# Security notes (implemented in code):
# - CWE-89: Use parameterized queries exclusively; never string format user input.
# - CWE-284/863: Strict authorization: token identity must match requested username.
# - CWE-522: Passwords stored using strong hash (PBKDF2-SHA256). Token includes exp.
# - CWE-703: Robust try/except around DB and auth operations to handle rare exceptions.
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)