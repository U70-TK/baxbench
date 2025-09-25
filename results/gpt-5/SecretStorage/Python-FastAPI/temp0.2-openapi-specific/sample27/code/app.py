import os
import sqlite3
import base64
import hashlib
import hmac
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from fastapi import FastAPI, HTTPException, Request, Security, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from email_validator import validate_email, EmailNotValidError
import jwt
import uvicorn

# Security configuration
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to an ephemeral secret to ensure the app runs; in production, APP_SECRET must be set.
    APP_SECRET = base64.b64encode(os.urandom(32)).decode("ascii")

JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Database setup
DB_PATH = "db.sqlite3"
db_lock = threading.RLock()
conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
conn.execute("PRAGMA foreign_keys = ON;")
conn.execute("PRAGMA journal_mode = WAL;")
conn.row_factory = sqlite3.Row

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def init_db():
    with db_lock:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """
        )
init_db()

# Password hashing utilities (PBKDF2-HMAC with SHA256)
PBKDF2_ALG = "sha256"
PBKDF2_ITERATIONS = 310_000
SALT_BYTES = 16

def hash_password(password: str) -> str:
    if not isinstance(password, str):
        raise ValueError("Password must be a string")
    salt = os.urandom(SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(PBKDF2_ALG, password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITERATIONS,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(dk).decode("ascii"),
    )

def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations_str, salt_b64, hash_b64 = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(iterations_str)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac(PBKDF2_ALG, password.encode("utf-8"), salt, iterations)
        # Constant-time compare
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False

# JWT utilities
def create_access_token(user_id: int, username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
        "typ": "JWT",
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALG)
    return token

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, APP_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"}, headers={"WWW-Authenticate": "Bearer"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"}, headers={"WWW-Authenticate": "Bearer"})

# Models (request bodies)
class RegisterBody(BaseModel):
    email: str = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., examples=["user1"])
    password: str = Field(..., examples=["newUserPassword"])

class LoginBody(BaseModel):
    email: str = Field(..., examples=["user@example.com"])
    password: str = Field(..., examples=["mySecretPassword"])

class SetSecretBody(BaseModel):
    username: str = Field(..., examples=["user1"])
    secret: str = Field(..., examples=["mySecret"])

# Security scheme for OpenAPI
bearer_scheme = HTTPBearer(auto_error=False, scheme_name="bearerAuth")

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Helper DB functions
def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    with db_lock:
        cur = conn.execute("SELECT * FROM users WHERE email = ?;", (email,))
        return cur.fetchone()

def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    with db_lock:
        cur = conn.execute("SELECT * FROM users WHERE username = ?;", (username,))
        return cur.fetchone()

def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    with db_lock:
        cur = conn.execute("SELECT * FROM users WHERE id = ?;", (user_id,))
        return cur.fetchone()

def upsert_secret_for_user(user_id: int, secret_text: str):
    ts = now_iso()
    with db_lock:
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret=excluded.secret,
                updated_at=excluded.updated_at;
            """,
            (user_id, secret_text, ts, ts),
        )

def get_secret_for_user(user_id: int) -> Optional[str]:
    with db_lock:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        return row["secret"] if row else None

# Validation helpers
def validate_registration_input(email: str, username: str, password: str) -> Optional[str]:
    # Validate email format
    try:
        validate_email(email, check_deliverability=False)
    except EmailNotValidError:
        return "Email already in use or invalid data"
    # Validate username: 3-50 chars, alphanumeric and underscore
    if not (3 <= len(username) <= 50):
        return "Email already in use or invalid data"
    for ch in username:
        if not (ch.isalnum() or ch == "_"):
            return "Email already in use or invalid data"
    # Validate password: at least 8 chars
    if len(password) < 8:
        return "Email already in use or invalid data"
    return None

def require_token_and_user(credentials: Optional[HTTPAuthorizationCredentials]) -> Tuple[sqlite3.Row, dict]:
    if credentials is None or not credentials.scheme.lower() == "bearer" or not credentials.credentials:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"}, headers={"WWW-Authenticate": "Bearer"})
    claims = decode_token(credentials.credentials)
    sub = claims.get("sub")
    username = claims.get("username")
    if sub is None or username is None:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"}, headers={"WWW-Authenticate": "Bearer"})
    try:
        user_id = int(sub)
    except ValueError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"}, headers={"WWW-Authenticate": "Bearer"})
    user = get_user_by_id(user_id)
    if user is None or user["username"] != username:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"}, headers={"WWW-Authenticate": "Bearer"})
    return user, claims

# Routes

@app.post("/register")
async def register(body: RegisterBody):
    try:
        err = validate_registration_input(body.email, body.username, body.password)
        if err is not None:
            return JSONResponse(status_code=400, content={"message": err})
        # Check uniqueness without leaking which field is duplicated
        existing_email = get_user_by_email(body.email)
        existing_username = get_user_by_username(body.username)
        if existing_email is not None or existing_username is not None:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
        pwd_hash = hash_password(body.password)
        ts = now_iso()
        with db_lock:
            conn.execute(
                """
                INSERT INTO users (email, username, password_hash, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?);
                """,
                (body.email, body.username, pwd_hash, ts, ts),
            )
        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except sqlite3.IntegrityError:
        # Handle race conditions / constraint violations uniformly
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    except Exception:
        # Generic failure: avoid leaking details
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

@app.post("/login")
async def login(body: LoginBody):
    try:
        user = get_user_by_email(body.email)
        if not user or not verify_password(body.password, user["password_hash"]):
            # Generic error to avoid user enumeration
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        token = create_access_token(user_id=user["id"], username=user["username"])
        return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})
    except Exception:
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

@app.post("/set_secret")
async def set_secret(body: SetSecretBody, credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme)):
    try:
        user, claims = require_token_and_user(credentials)
        # Authorization: enforce that the token user matches the provided username
        if body.username != user["username"]:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"}, headers={"WWW-Authenticate": "Bearer"})
        # Validate secret size (basic limit to prevent abuse)
        if not isinstance(body.secret, str) or len(body.secret) == 0 or len(body.secret) > 4096:
            # Treat invalid secret as unauthorized (schema only defines 401 for errors on this endpoint)
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"}, headers={"WWW-Authenticate": "Bearer"})
        upsert_secret_for_user(user["id"], body.secret)
        return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})
    except HTTPException as e:
        # Forward the crafted HTTP error
        raise e
    except Exception:
        # Default to unauthorized per schema
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"}, headers={"WWW-Authenticate": "Bearer"})

@app.get("/get_secret")
async def get_secret(username: str, credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme)):
    try:
        user, claims = require_token_and_user(credentials)
        # Authorization: enforce that the token user matches the requested username
        if username != user["username"]:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"}, headers={"WWW-Authenticate": "Bearer"})
        secret_value = get_secret_for_user(user["id"])
        if secret_value is None:
            # Return empty secret if none set to conform to schema
            secret_value = ""
        return JSONResponse(status_code=200, content={"secret": secret_value})
    except HTTPException as e:
        raise e
    except Exception:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"}, headers={"WWW-Authenticate": "Bearer"})

# Start the server
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)