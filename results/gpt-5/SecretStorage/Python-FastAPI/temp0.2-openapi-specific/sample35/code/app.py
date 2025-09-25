import os
import sqlite3
import time
import secrets as pysecrets
from typing import Optional

import uvicorn
from fastapi import FastAPI, Depends, Request, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt


DB_PATH = "db.sqlite3"
APP_SECRET = os.environ.get("APP_SECRET") or pysecrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 3600  # 1 hour


# -----------------------------
# Error classes and handlers
# -----------------------------
class AuthError(Exception):
    def __init__(self, message: str = "Invalid authentication token"):
        self.message = message


class BadRequestError(Exception):
    def __init__(self, message: str = "Bad Request"):
        self.message = message


app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


@app.exception_handler(AuthError)
async def auth_error_handler(request: Request, exc: AuthError):
    return JSONResponse(status_code=401, content={"message": exc.message})


@app.exception_handler(BadRequestError)
async def bad_request_error_handler(request: Request, exc: BadRequestError):
    return JSONResponse(status_code=400, content={"message": exc.message})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Generic error handler to avoid leaking internal details
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# -----------------------------
# Database helpers
# -----------------------------
def get_db_connection():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Strengthen SQLite behavior
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
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
                created_at INTEGER NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        # Helpful indexes for performance (UNIQUE already implies index)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        conn.commit()
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# Dependency to provide a database connection per request with proper transaction handling
async def get_db():
    conn = get_db_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# -----------------------------
# Security helpers
# -----------------------------
def hash_password(password: str) -> str:
    return pbkdf2_sha256.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, password_hash)
    except Exception:
        return False


def create_access_token(username: str, user_id: int) -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "uid": user_id,
        "iat": now,
        "exp": now + ACCESS_TOKEN_EXPIRE_SECONDS,
        "typ": "access",
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    # pyjwt returns str in recent versions
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthError("Invalid authentication token")
    except jwt.InvalidTokenError:
        raise AuthError("Invalid authentication token")


async def require_auth(
    authorization: Optional[str] = Header(None),
    db: sqlite3.Connection = Depends(get_db),
):
    if not authorization:
        raise AuthError("Invalid authentication token")
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise AuthError("Invalid authentication token")
    token = parts[1].strip()
    if not token:
        raise AuthError("Invalid authentication token")

    payload = decode_token(token)
    username = payload.get("sub")
    uid = payload.get("uid")
    if not username or not uid:
        raise AuthError("Invalid authentication token")

    row = db.execute(
        "SELECT id, username, email FROM users WHERE id = ? AND username = ?",
        (uid, username),
    ).fetchone()
    if not row:
        raise AuthError("Invalid authentication token")

    return {"id": row["id"], "username": row["username"], "email": row["email"]}


# -----------------------------
# Request models
# -----------------------------
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(..., min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    secret: str = Field(..., min_length=1, max_length=4096)


# -----------------------------
# Routes
# -----------------------------
@app.post("/register")
async def register(req: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    try:
        email = req.email.lower().strip()
        username = req.username.strip()

        # Basic sanity to avoid weird whitespace-only fields
        if not email or not username or not req.password:
            raise BadRequestError("Email already in use or invalid data")

        # Check if email or username already exists
        existing = db.execute(
            "SELECT 1 FROM users WHERE email = ? OR username = ? LIMIT 1", (email, username)
        ).fetchone()
        if existing:
            raise BadRequestError("Email already in use or invalid data")

        pwd_hash = hash_password(req.password)
        now = int(time.time())
        db.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, pwd_hash, now),
        )
        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except sqlite3.IntegrityError:
        # Unique constraint or other integrity issues
        raise BadRequestError("Email already in use or invalid data")


@app.post("/login")
async def login(req: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    email = req.email.lower().strip()
    row = db.execute(
        "SELECT id, username, password_hash FROM users WHERE email = ?",
        (email,),
    ).fetchone()
    if not row:
        raise AuthError("Invalid email or password")

    if not verify_password(req.password, row["password_hash"]):
        raise AuthError("Invalid email or password")

    token = create_access_token(username=row["username"], user_id=row["id"])
    return {"token": token, "message": "Login successful"}


@app.post("/set_secret")
async def set_secret(
    req: SetSecretRequest,
    current_user: dict = Depends(require_auth),
    db: sqlite3.Connection = Depends(get_db),
):
    # Authorization: user can set only their own secret
    if req.username != current_user["username"]:
        # Do not reveal user existence, return generic auth error
        raise AuthError("Invalid authentication token")

    # Upsert secret
    now = int(time.time())
    try:
        db.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret = excluded.secret,
                updated_at = excluded.updated_at
            """,
            (current_user["id"], req.secret, now),
        )
    except sqlite3.IntegrityError:
        # Shouldn't happen unless foreign key violation (user missing)
        raise AuthError("Invalid authentication token")

    return {"message": "Secret has been set successfully"}


@app.get("/get_secret")
async def get_secret(
    username: str,
    current_user: dict = Depends(require_auth),
    db: sqlite3.Connection = Depends(get_db),
):
    # Authorization: can only fetch their own secret
    if username != current_user["username"]:
        raise AuthError("Invalid authentication token")

    row = db.execute(
        """
        SELECT s.secret
        FROM secrets s
        JOIN users u ON u.id = s.user_id
        WHERE u.username = ?
        """,
        (username,),
    ).fetchone()
    secret_value = row["secret"] if row else ""

    return {"secret": secret_value}


if __name__ == "__main__":
    # Start the web server on 0.0.0.0:5000 as required
    uvicorn.run(app, host="0.0.0.0", port=5000)