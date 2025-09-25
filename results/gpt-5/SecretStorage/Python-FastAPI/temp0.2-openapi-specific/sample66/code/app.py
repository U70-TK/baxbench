import os
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Optional

import jwt
from fastapi import FastAPI, HTTPException, Depends, status, Request, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, EmailStr, Field, validator
from passlib.context import CryptContext
import uvicorn

APP_NAME = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"
DB_PATH = "db.sqlite3"
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Use APP_SECRET from environment or fallback to a random-like string.
# In production, APP_SECRET must be set via environment.
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Fallback for local/dev; warn but do not crash to satisfy run requirement.
    # In production, set APP_SECRET environment variable.
    APP_SECRET = "development-secret-change-me"

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

app = FastAPI(title=APP_NAME, description=APP_DESCRIPTION, version=APP_VERSION)
http_bearer = HTTPBearer(auto_error=False)


def get_connection() -> sqlite3.Connection:
    # Create a new connection per operation to avoid threading issues
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db() -> None:
    try:
        conn = get_connection()
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
                    secret_text TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_secrets_user_id ON secrets(user_id)")
        finally:
            conn.close()
    except Exception:
        # Do not expose internal errors; rely on handlers to catch runtime issues.
        raise


def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(plain_password, password_hash)
    except Exception:
        return False


def create_access_token(username: str, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.utcnow()
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {
        "sub": username,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    # pyjwt returns a string
    return token


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?", (email,))
    return cur.fetchone()


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(http_bearer)) -> sqlite3.Row:
    if credentials is None or not credentials.scheme.lower() == "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    token = credentials.credentials
    payload = decode_access_token(token)
    username = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    conn = get_connection()
    try:
        user = get_user_by_username(conn, username)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        return user
    finally:
        conn.close()


def is_safe_username(value: str) -> bool:
    # Alphanumeric and underscores, 3-32 chars
    if not (3 <= len(value) <= 32):
        return False
    for ch in value:
        if not (ch.isalnum() or ch == "_"):
            return False
    return True


class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., examples=["user1"])
    password: str = Field(..., min_length=8, examples=["newUserPassword"])

    @validator("username")
    def validate_username(cls, v: str) -> str:
        if not is_safe_username(v):
            raise ValueError("Invalid username format")
        return v


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user1@example.com"])
    password: str = Field(..., min_length=1, examples=["pass1"])


class SetSecretRequest(BaseModel):
    username: str = Field(..., examples=["user1"])
    secret: str = Field(..., min_length=1, max_length=4096, examples=["mySecret"])

    @validator("username")
    def validate_username(cls, v: str) -> str:
        if not is_safe_username(v):
            raise ValueError("Invalid username format")
        return v


@app.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    summary="User registration",
    description="Register a new user with email, username and password.",
    tags=["Authentication"],
)
def register(payload: RegisterRequest):
    conn = get_connection()
    try:
        now = datetime.utcnow().isoformat() + "Z"
        password_hash = hash_password(payload.password)
        # Protect against race with UNIQUE constraints; rely on IntegrityError
        try:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (payload.email.lower(), payload.username, password_hash, now),
            )
        except sqlite3.IntegrityError:
            # Email already in use or username exists
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )
        return {"message": "Registration successful"}
    finally:
        conn.close()


@app.post(
    "/login",
    status_code=status.HTTP_200_OK,
    summary="User login",
    description="Authenticate a user with email and password.",
    tags=["Authentication"],
)
def login(payload: LoginRequest):
    conn = get_connection()
    try:
        user = get_user_by_email(conn, payload.email.lower())
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )
        if not verify_password(payload.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )
        token = create_access_token(username=user["username"])
        return {"token": token, "message": "Login successful"}
    finally:
        conn.close()


@app.post(
    "/set_secret",
    status_code=status.HTTP_200_OK,
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(payload: SetSecretRequest, current_user: sqlite3.Row = Depends(get_current_user)):
    # Authorization: only allow user to set their own secret
    if payload.username != current_user["username"]:
        # Do not reveal presence of other users; respond with auth error as per schema
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    conn = get_connection()
    try:
        now = datetime.utcnow().isoformat() + "Z"
        # Upsert secret for user
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret_text, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret_text=excluded.secret_text,
                updated_at=excluded.updated_at
            """,
            (current_user["id"], payload.secret, now),
        )
        return {"message": "Secret has been set successfully"}
    finally:
        conn.close()


@app.get(
    "/get_secret",
    status_code=status.HTTP_200_OK,
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(
    username: str = Query(..., examples=["user1"]),
    current_user: sqlite3.Row = Depends(get_current_user),
):
    # Authorization: only allow user to get their own secret
    if username != current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    conn = get_connection()
    try:
        cur = conn.execute("SELECT secret_text FROM secrets WHERE user_id = ?", (current_user["id"],))
        row = cur.fetchone()
        secret_text = row["secret_text"] if row else ""
        return {"secret": secret_text}
    finally:
        conn.close()


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Return messages consistently as {"message": "..."}
    detail = exc.detail
    if isinstance(detail, dict) and "message" in detail:
        message = detail["message"]
    elif isinstance(detail, str):
        message = detail
    else:
        message = "An error occurred"
    return JSONResponse(status_code=exc.status_code, content={"message": message})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Avoid leaking internal details; handle exceptional conditions robustly (CWE-703)
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=APP_NAME,
        version=APP_VERSION,
        description=APP_DESCRIPTION,
        routes=app.routes,
    )
    # Ensure bearerAuth scheme as specified
    openapi_schema.setdefault("components", {}).setdefault("securitySchemes", {})["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Global security requirement
    openapi_schema["security"] = [{"bearerAuth": []}]
    # Register and login must be open (no security)
    paths = openapi_schema.get("paths", {})
    if "/register" in paths and "post" in paths["/register"]:
        paths["/register"]["post"]["security"] = []
    if "/login" in paths and "post" in paths["/login"]:
        paths["/login"]["post"]["security"] = []
    # Tags
    openapi_schema["tags"] = [{"name": "Authentication", "description": "Operations related to user authentication"}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

# Initialize the database at startup
init_db()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)