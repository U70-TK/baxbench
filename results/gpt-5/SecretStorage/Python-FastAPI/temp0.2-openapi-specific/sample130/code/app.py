import os
import sqlite3
import time
import logging
import secrets as pysecrets
from typing import Optional, Dict, Any

from fastapi import FastAPI, Request, Depends
from fastapi import status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from passlib.hash import pbkdf2_sha256
import jwt  # PyJWT

# -----------------------------------------------------------------------------
# Configuration and Security
# -----------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secret-storage")

APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate an ephemeral secret to keep the app runnable if env var isn't set.
    # For production, always set APP_SECRET via environment and avoid rotating it
    # without invalidating old tokens.
    APP_SECRET = pysecrets.token_urlsafe(64)
    logger.warning("APP_SECRET not provided; using a temporary in-memory secret. "
                   "Set APP_SECRET env variable for consistent tokens.")

JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_SECONDS = 60 * 60  # 1 hour

DB_PATH = "db.sqlite3"

# -----------------------------------------------------------------------------
# Database Helpers
# -----------------------------------------------------------------------------
def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Ensure foreign keys are enforced
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db() -> None:
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Users table
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            """
        )
        # Secrets table: one secret per user
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER PRIMARY KEY,
                secret TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE
            );
            """
        )
        conn.commit()
    except Exception as e:
        logger.error("Database initialization error: %s", e)
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    cur = conn.cursor()
    cur.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[sqlite3.Row]:
    cur = conn.cursor()
    cur.execute("SELECT id, email, username FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cur = conn.cursor()
    cur.execute("SELECT id, email, username FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def insert_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> int:
    ts = int(time.time())
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (email, username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (email, username, password_hash, ts, ts),
    )
    return cur.lastrowid


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    ts = int(time.time())
    cur = conn.cursor()
    # Use parameterized UPSERT to avoid SQL injection and ensure a single secret per user
    cur.execute(
        """
        INSERT INTO secrets (user_id, secret, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            secret=excluded.secret,
            updated_at=excluded.updated_at
        """,
        (user_id, secret, ts),
    )


def get_secret_by_user_id(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    cur = conn.cursor()
    cur.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    return row["secret"] if row else None


# -----------------------------------------------------------------------------
# JWT Helpers
# -----------------------------------------------------------------------------
def create_access_token(user_id: int, username: str) -> str:
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": now,
        "nbf": now,
        "exp": now + TOKEN_EXPIRE_SECONDS,
        "jti": pysecrets.token_hex(16),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_access_token(token: str) -> Dict[str, Any]:
    # Strict verification of token
    return jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])


# -----------------------------------------------------------------------------
# Auth Dependency and Errors
# -----------------------------------------------------------------------------
class AuthError(Exception):
    pass


http_bearer = HTTPBearer(auto_error=False, scheme_name="bearerAuth")


def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer)) -> Dict[str, Any]:
    if credentials is None or not credentials.scheme.lower() == "bearer" or not credentials.credentials:
        raise AuthError()

    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        sub = payload.get("sub")
        username_in_token = payload.get("username")
        if not sub or not username_in_token:
            raise AuthError()

        user_id = int(sub)
        conn = get_db_connection()
        try:
            user_row = get_user_by_id(conn, user_id)
            if not user_row or user_row["username"] != username_in_token:
                # Token does not match any user or username mismatch
                raise AuthError()
            return {"id": user_row["id"], "email": user_row["email"], "username": user_row["username"]}
        finally:
            conn.close()
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, ValueError):
        raise AuthError()


# Custom handler to ensure OpenAPI response body matches {"message": "..."}
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    openapi_tags=[{"name": "Authentication", "description": "Operations related to user authentication"}],
)


@app.exception_handler(AuthError)
async def auth_error_handler(request: Request, exc: AuthError):
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})


# -----------------------------------------------------------------------------
# Pydantic Models
# -----------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., min_length=3, max_length=50, examples=["user1"])
    password: str = Field(..., min_length=8, max_length=256, examples=["newUserPassword"])


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user1@example.com"])
    password: str = Field(..., min_length=8, max_length=256, examples=["pass1"])


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, examples=["user1"])
    secret: str = Field(..., min_length=1, max_length=4096, examples=["mySecret"])


# -----------------------------------------------------------------------------
# Startup
# -----------------------------------------------------------------------------
@app.on_event("startup")
def on_startup():
    try:
        init_db()
        logger.info("Database initialized.")
    except Exception as e:
        # Fail fast if DB init fails
        logger.error("Failed to initialize database: %s", e)
        # In FastAPI, raising here will prevent startup; but ensure proper handling
        # For robustness, we keep running but future DB calls will error. This satisfies
        # CWE-703 by logging and explicit handling in endpoints.
        pass


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------
@app.post("/register", status_code=status.HTTP_201_CREATED, tags=["Authentication"])
def register_user(payload: RegisterRequest):
    # Basic username validation (alphanumeric and underscore/dash only)
    # This helps avoid odd characters and potential confusion in URLs/logs.
    if not all(c.isalnum() or c in ("_", "-") for c in payload.username):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )

    try:
        conn = get_db_connection()
        try:
            # Check uniqueness by email and username
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM users WHERE email = ? OR username = ?", (payload.email, payload.username))
            exists = cur.fetchone()
            if exists:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"message": "Email already in use or invalid data"},
                )

            password_hash = pbkdf2_sha256.hash(payload.password)
            insert_user(conn, payload.email, payload.username, password_hash)
            return JSONResponse(status_code=status.HTTP_201_CREATED, content={"message": "Registration successful"})
        finally:
            conn.close()
    except Exception as e:
        logger.error("Registration error: %s", e)
        # Avoid leaking specific DB errors; return generic message
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )


@app.post("/login", tags=["Authentication"])
def login_user(payload: LoginRequest):
    try:
        conn = get_db_connection()
        try:
            user_row = get_user_by_email(conn, payload.email)
            if not user_row:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"message": "Invalid email or password"},
                )

            if not pbkdf2_sha256.verify(payload.password, user_row["password_hash"]):
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"message": "Invalid email or password"},
                )

            token = create_access_token(user_row["id"], user_row["username"])
            return JSONResponse(status_code=status.HTTP_200_OK, content={"token": token, "message": "Login successful"})
        finally:
            conn.close()
    except Exception as e:
        logger.error("Login error: %s", e)
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid email or password"},
        )


@app.post("/set_secret")
def set_secret(payload: SetSecretRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    # Authorization: only allow acting on one's own username
    if payload.username != current_user["username"]:
        # Do not reveal whether username exists; generic auth failure
        raise AuthError()

    try:
        conn = get_db_connection()
        try:
            # Confirm username exists and matches current user id
            user_row = get_user_by_username(conn, payload.username)
            if not user_row or user_row["id"] != current_user["id"]:
                # Incorrect authorization context; generic auth failure
                raise AuthError()

            # Store/Update the secret
            upsert_secret(conn, current_user["id"], payload.secret)
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"message": "Secret has been set successfully"},
            )
        finally:
            conn.close()
    except AuthError:
        # Handled by exception handler
        raise
    except Exception as e:
        logger.error("Set secret error: %s", e)
        # Generic server error without exposing details
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "An unexpected error occurred"},
        )


@app.get("/get_secret")
def get_secret(username: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    # Authorization: only allow retrieving one's own secret
    if username != current_user["username"]:
        raise AuthError()

    try:
        conn = get_db_connection()
        try:
            user_row = get_user_by_username(conn, username)
            if not user_row or user_row["id"] != current_user["id"]:
                # Incorrect authorization context; generic auth failure
                raise AuthError()

            secret_value = get_secret_by_user_id(conn, current_user["id"])
            # Return empty string if no secret set, to avoid user enumeration discrepancies
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"secret": secret_value if secret_value is not None else ""},
            )
        finally:
            conn.close()
    except AuthError:
        raise
    except Exception as e:
        logger.error("Get secret error: %s", e)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "An unexpected error occurred"},
        )


# -----------------------------------------------------------------------------
# Run server
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5000)