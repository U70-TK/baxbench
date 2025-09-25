import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn
import secrets as _secrets

# Application configuration
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback for robustness (CWE-703): Use a strong temporary secret if not provided.
    # Note: Tokens will be invalid after restart if APP_SECRET is not set.
    APP_SECRET = _secrets.token_urlsafe(64)
    print("WARNING: APP_SECRET not set. Using a temporary secret key; tokens will be invalid after restart.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
DB_PATH = "db.sqlite3"

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Database utilities
def get_db() -> sqlite3.Connection:
    # Create a new connection per request to avoid threading issues with sqlite3
    conn = sqlite3.connect(DB_PATH, isolation_level=None, timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=10000;")
    except sqlite3.Error:
        # Fail silently here; PRAGMAs may not be available in some contexts
        pass
    return conn

def init_db():
    conn = get_db()
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS secrets (
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            """)
    finally:
        conn.close()

@app.on_event("startup")
def on_startup():
    init_db()

# Data access helpers (use parameterized queries to prevent SQL injection - CWE-89)
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

def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return cur.fetchone()
    except sqlite3.Error:
        return None

def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> bool:
    now = datetime.now(timezone.utc).isoformat()
    try:
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (email, username, password_hash, now, now),
        )
        return True
    except sqlite3.IntegrityError:
        return False
    except sqlite3.Error:
        return False

def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> bool:
    now = datetime.now(timezone.utc).isoformat()
    try:
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=excluded.updated_at
            """,
            (user_id, secret, now, now),
        )
        return True
    except sqlite3.Error:
        return False

def get_secret_by_username(conn: sqlite3.Connection, username: str) -> Optional[str]:
    try:
        cur = conn.execute(
            """
            SELECT s.secret FROM secrets s
            JOIN users u ON s.user_id = u.id
            WHERE u.username = ?
            """,
            (username,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        # sqlite3.Row supports key lookup
        if "secret" in row.keys():
            return row["secret"]
        return row[0]
    except sqlite3.Error:
        return None

# Security helpers
def create_access_token(user_row: sqlite3.Row) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_row["id"]),
        "username": user_row["username"],
        "email": user_row["email"],
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=ALGORITHM)
    return token

def parse_bearer_token(request: Request) -> Optional[str]:
    auth = request.headers.get("Authorization")
    if not auth:
        return None
    parts = auth.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None

def get_user_from_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None
    try:
        user_id = int(payload.get("sub", "0"))
    except (ValueError, TypeError):
        return None
    conn = get_db()
    try:
        user = get_user_by_id(conn, user_id)
    finally:
        conn.close()
    if not user:
        return None
    return {"id": user["id"], "email": user["email"], "username": user["username"]}

# Pydantic models (validate inputs to avoid CWE-703 and enforce secure handling)
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    secret: str = Field(min_length=1, max_length=10000)

# Routes
@app.post("/register")
def register(req: RegisterRequest):
    try:
        conn = get_db()
        try:
            # Check for duplicates
            if get_user_by_email(conn, req.email) is not None or get_user_by_username(conn, req.username) is not None:
                return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
            # Hash the password securely (CWE-522)
            password_hash = pbkdf2_sha256.hash(req.password)
            created = create_user(conn, req.email, req.username, password_hash)
            if not created:
                return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
            return {"message": "Registration successful"}
        finally:
            conn.close()
    except Exception:
        # Handle unexpected errors gracefully (CWE-703)
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

@app.post("/login")
def login(req: LoginRequest):
    try:
        conn = get_db()
        try:
            user = get_user_by_email(conn, req.email)
            if not user:
                return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
            if not pbkdf2_sha256.verify(req.password, user["password_hash"]):
                return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
            token = create_access_token(user)
            return {"token": token, "message": "Login successful"}
        finally:
            conn.close()
    except Exception:
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

@app.post("/set_secret")
def set_secret(req: SetSecretRequest, request: Request):
    token = parse_bearer_token(request)
    if not token:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    user = get_user_from_token(token)
    if not user:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    # Authorization check (CWE-284, CWE-863): ensure user can only set their own secret
    if req.username != user["username"]:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    try:
        conn = get_db()
        try:
            db_user = get_user_by_username(conn, req.username)
            if not db_user:
                # Do not leak existence; return generic unauthorized
                return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
            if not upsert_secret(conn, db_user["id"], req.secret):
                # If DB error occurs, treat as unauthorized to avoid info leakage
                return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
            return {"message": "Secret has been set successfully"}
        finally:
            conn.close()
    except Exception:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

@app.get("/get_secret")
def get_secret(username: str, request: Request):
    token = parse_bearer_token(request)
    if not token:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    user = get_user_from_token(token)
    if not user:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    # Authorization check (CWE-284, CWE-863): ensure user can only access their own secret
    if username != user["username"]:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    try:
        conn = get_db()
        try:
            secret = get_secret_by_username(conn, username)
            # Return empty string if no secret found, do not leak info
            return {"secret": secret if secret is not None else ""}
        finally:
            conn.close()
    except Exception:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

if __name__ == "__main__":
    # Start the web server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)