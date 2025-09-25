import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn

# Constants
DB_PATH = "db.sqlite3"
TOKEN_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Load APP_SECRET from environment or generate a random one
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to a strong random secret (discouraged for production; prefer env variable)
    APP_SECRET = uuid.uuid4().hex + uuid.uuid4().hex

app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

# Security schemes
http_bearer = HTTPBearer(auto_error=False)


# Database helpers
def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 3000;")
    except sqlite3.Error:
        # If PRAGMA fails, continue; connection is still usable
        pass
    return conn


def init_db() -> None:
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
            );
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
            );
            """
        )
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?;", (email,))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?;", (username,))
    return cur.fetchone()


def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> Tuple[bool, Optional[str]]:
    try:
        conn.execute(
            "INSERT INTO users(email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (email, username, password_hash, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        return True, None
    except sqlite3.IntegrityError as e:
        conn.rollback()
        # Likely duplicate email/username
        return False, "Email already in use or invalid data"
    except sqlite3.Error:
        conn.rollback()
        return False, "Internal server error"


def set_user_secret(conn: sqlite3.Connection, user_id: int, secret_text: str) -> Tuple[bool, Optional[str]]:
    try:
        conn.execute(
            """
            INSERT INTO secrets(user_id, secret_text, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret_text=excluded.secret_text,
                updated_at=excluded.updated_at;
            """,
            (user_id, secret_text, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        return True, None
    except sqlite3.Error:
        conn.rollback()
        return False, "Internal server error"


def get_secret_by_username(conn: sqlite3.Connection, username: str) -> Optional[str]:
    cur = conn.execute(
        """
        SELECT s.secret_text
        FROM secrets s
        JOIN users u ON u.id = s.user_id
        WHERE u.username = ?;
        """,
        (username,),
    )
    row = cur.fetchone()
    return row["secret_text"] if row else None


# Models
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


# Exception handlers to align with schema
@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request, exc: HTTPException):
    # Ensure response body uses {"message": "..."} as per schema
    detail = exc.detail if isinstance(exc.detail, str) else "An error occurred"
    return JSONResponse(status_code=exc.status_code, content={"message": detail})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError):
    # Standardize validation errors to 400 for consistency with provided schema
    return JSONResponse(status_code=400, content={"message": "Invalid request data"})


# Security helpers
def create_access_token(username: str, email: str, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
        "jti": uuid.uuid4().hex,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=TOKEN_ALGORITHM)
    return token


def require_valid_token(credentials: HTTPAuthorizationCredentials = Security(http_bearer)) -> dict:
    if credentials is None or not credentials.scheme.lower() == "bearer":
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    token = credentials.credentials
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[TOKEN_ALGORITHM])
        username = payload.get("sub")
        email = payload.get("email")
        if not username or not email:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        # Optional: ensure user still exists
        conn = get_db_connection()
        try:
            user = get_user_by_username(conn, username)
        finally:
            conn.close()
        if user is None or user["email"] != email:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        return {"username": username, "email": email, "payload": payload}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")


# Routes
@app.post(
    "/register",
    tags=["Authentication"],
    openapi_extra={"security": []},
    status_code=201,
)
def register(req: RegisterRequest):
    conn = get_db_connection()
    try:
        # Normalize fields (trim whitespace)
        email = req.email.strip()
        username = req.username.strip()
        password = req.password

        if not email or not username or not password:
            raise HTTPException(status_code=400, detail="Email already in use or invalid data")

        # Hash password securely
        password_hash = pbkdf2_sha256.hash(password)

        ok, err = create_user(conn, email, username, password_hash)
        if not ok:
            if err == "Email already in use or invalid data":
                raise HTTPException(status_code=400, detail=err)
            # Fallback for unexpected errors
            raise HTTPException(status_code=500, detail="Internal server error")

        return {"message": "Registration successful"}
    finally:
        conn.close()


@app.post(
    "/login",
    tags=["Authentication"],
    openapi_extra={"security": []},
)
def login(req: LoginRequest):
    conn = get_db_connection()
    try:
        email = req.email.strip()
        password = req.password

        user = get_user_by_email(conn, email)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid email or password")

        stored_hash = user["password_hash"]
        if not pbkdf2_sha256.verify(password, stored_hash):
            raise HTTPException(status_code=401, detail="Invalid email or password")

        token = create_access_token(username=user["username"], email=user["email"])
        return {"token": token, "message": "Login successful"}
    finally:
        conn.close()


@app.post("/set_secret")
def set_secret(req: SetSecretRequest, token_info: dict = Depends(require_valid_token)):
    # Authorization: token's username must match provided username
    if req.username.strip() != token_info["username"]:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, req.username.strip())
        if not user:
            # If user doesn't exist, treat as unauthorized to avoid info disclosure
            raise HTTPException(status_code=401, detail="Invalid authentication token")

        ok, err = set_user_secret(conn, user_id=user["id"], secret_text=req.secret)
        if not ok:
            if err == "Internal server error":
                raise HTTPException(status_code=500, detail=err)
            raise HTTPException(status_code=500, detail="Internal server error")

        return {"message": "Secret has been set successfully"}
    finally:
        conn.close()


@app.get("/get_secret")
def get_secret(username: str, token_info: dict = Depends(require_valid_token)):
    # Authorization: token's username must match requested username
    if username.strip() != token_info["username"]:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        # Confirm user exists
        user = get_user_by_username(conn, username.strip())
        if not user:
            # Return empty secret to avoid leaking whether user exists; still authorized as per token
            return {"secret": ""}

        secret_text = get_secret_by_username(conn, username.strip())
        return {"secret": secret_text or ""}
    finally:
        conn.close()


# Customize OpenAPI to include bearerAuth as specified
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Secret Storage",
        version="1.0.0",
        description="A secure cloud storage app for string secrets.",
        routes=app.routes,
    )
    # Ensure security scheme appears as described
    openapi_schema.setdefault("components", {})
    openapi_schema["components"].setdefault("securitySchemes", {})
    openapi_schema["components"]["securitySchemes"]["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Global security requirement
    openapi_schema["security"] = [{"bearerAuth": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


@app.on_event("startup")
def on_startup():
    # Initialize database tables
    try:
        init_db()
    except Exception:
        # If DB init fails, the app should still start, but operations will fail with 500.
        pass


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)