import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Generator, Optional

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn


# Constants
DB_PATH = os.path.join(os.getcwd(), "db.sqlite3")
ACCESS_TOKEN_EXPIRE_MINUTES = 60
JWT_ALGORITHM = "HS256"


def get_app_secret() -> str:
    """Get application secret from environment or generate a random one."""
    secret = os.getenv("APP_SECRET")
    if not secret:
        # Generate an ephemeral secret to allow the app to start
        # In production, always set APP_SECRET securely!
        secret = os.urandom(32).hex()
        print("Warning: APP_SECRET not set. Generated ephemeral secret for runtime.")
    return secret


APP_SECRET = get_app_secret()


def create_tables() -> None:
    """Initialize the database tables if they do not exist."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
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
                user_id INTEGER PRIMARY KEY,
                secret_text TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
    except Exception as e:
        # Fail fast during startup with a clear message
        print(f"Database initialization error: {e}")
        raise
    finally:
        conn.close()


def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Provide a SQLite connection per request, safely closed after use."""
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()


def hash_password(password: str) -> str:
    return pbkdf2_sha256.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, password_hash)
    except Exception:
        # In case of invalid hash formats
        return False


def create_access_token(*, user_id: int, username: str, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "uid": user_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def get_user_by_email(db: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = db.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def get_user_by_username(db: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = db.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def set_user_secret(db: sqlite3.Connection, user_id: int, secret_text: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    try:
        # Try to update; if nothing updated, insert
        cur = db.execute(
            "UPDATE secrets SET secret_text = ?, updated_at = ? WHERE user_id = ?",
            (secret_text, now, user_id),
        )
        if cur.rowcount == 0:
            db.execute(
                "INSERT INTO secrets (user_id, secret_text, updated_at) VALUES (?, ?, ?)",
                (user_id, secret_text, now),
            )
        db.commit()
    except sqlite3.Error:
        # Roll back on error
        db.rollback()
        raise


def get_user_secret(db: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = db.execute("SELECT secret_text FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if row is None:
        return None
    return row["secret_text"]


# Pydantic models for request bodies
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    secret: str = Field(min_length=1, max_length=4096)


# FastAPI application
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


# Security scheme
bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: sqlite3.Connection = Depends(get_db),
) -> sqlite3.Row:
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    token = credentials.credentials
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        uid = payload.get("uid")
        sub = payload.get("sub")
        if not uid or not sub:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    # Fetch user to ensure token refers to a valid user
    try:
        cur = db.execute("SELECT id, email, username FROM users WHERE id = ? AND username = ?", (uid, sub))
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        return user
    except sqlite3.Error:
        # Database error treated as unauthorized to avoid leaking details
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


# Exception handlers to return "message" field per schema
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Transform default exception format {"detail": ...} into {"message": ...}
    detail = exc.detail
    if isinstance(detail, dict):
        msg = detail.get("message") or "An error occurred"
    elif isinstance(detail, str):
        msg = detail
    else:
        msg = "An error occurred"
    return JSONResponse(status_code=exc.status_code, content={"message": msg})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # General safety net to avoid unhandled crashes leaking details
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


@app.on_event("startup")
def on_startup():
    create_tables()


# Routes

@app.post(
    "/register",
    status_code=201,
    summary="User registration",
    description="Register a new user with email, username and password.",
)
async def register(req: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    try:
        # Basic normalization
        email = req.email.lower().strip()
        username = req.username.strip()

        password_hash = hash_password(req.password)
        now = datetime.now(timezone.utc).isoformat()

        db.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, now),
        )
        db.commit()
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Unique constraint violation or invalid data
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")
    except sqlite3.Error:
        # Other database errors
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
)
async def login(req: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    try:
        email = req.email.lower().strip()
        user = get_user_by_email(db, email)
        if not user:
            # Avoid revealing whether the email exists
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        if not verify_password(req.password, user["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        token = create_access_token(user_id=user["id"], username=user["username"])
        return {"token": token, "message": "Login successful"}
    except sqlite3.Error:
        # Treat DB errors as auth failures to avoid leaking details
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
async def set_secret(
    req: SetSecretRequest,
    current_user: sqlite3.Row = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    try:
        # Authorization: token must belong to the username in the request to prevent CWE-863
        if current_user["username"] != req.username.strip():
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

        set_user_secret(db, current_user["id"], req.secret)
        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
async def get_secret(username: str, current_user: sqlite3.Row = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    try:
        # Authorization: user can only retrieve their own secret
        if current_user["username"] != username.strip():
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

        # Fetch the secret for the current user
        secret = get_user_secret(db, current_user["id"])
        # If not set, return empty string to adhere to schema (no error specified for missing secret)
        return {"secret": secret if secret is not None else ""}
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000 without using streaming responses
    uvicorn.run(app, host="0.0.0.0", port=5000)