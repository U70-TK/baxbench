import os
import sqlite3
import time
import secrets as std_secrets
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Request, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from passlib.context import CryptContext
import jwt
import uvicorn

APP_NAME = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

DB_PATH = "db.sqlite3"

# Load application secret for JWT
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate an ephemeral secret if none provided (for development)
    # In production, always set APP_SECRET!
    APP_SECRET = std_secrets.token_urlsafe(64)
    print("WARNING: APP_SECRET not set. Using a temporary secret key. Set APP_SECRET env variable in production.")

# Password hashing context (secure at-rest for passwords)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# FastAPI app
app = FastAPI(title=APP_NAME, description=APP_DESCRIPTION, version=APP_VERSION)

# HTTP Bearer security scheme for OpenAPI
bearer_security = HTTPBearer(auto_error=False, scheme_name="bearerAuth")


def get_db_connection() -> sqlite3.Connection:
    """
    Returns a new SQLite connection with safe settings.
    Use parameterized queries exclusively to prevent SQL injection (CWE-89).
    """
    conn = sqlite3.connect(DB_PATH, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Enforce foreign keys
    conn.execute("PRAGMA foreign_keys = ON;")
    # Journal mode for better durability
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
    except sqlite3.Error:
        pass
    return conn


def init_db():
    """
    Initialize the database schema, idempotently.
    """
    conn = None
    try:
        conn = get_db_connection()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER PRIMARY KEY,
                secret TEXT NOT NULL,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
    except sqlite3.Error as e:
        # Handle exceptional conditions gracefully (CWE-703)
        print(f"Database initialization error: {e}")
        raise
    finally:
        if conn:
            conn.close()


# Initialize database at startup
init_db()


# Pydantic models (input validation)
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    # Allow any length to avoid rejecting existing weak passwords during login.
    # Registration enforces a stronger minimum.
    password: str = Field(min_length=1, max_length=128)


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    secret: str = Field(min_length=1, max_length=8192)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        return False


def create_access_token(username: str, user_id: int, expires_in_seconds: int = 3600) -> str:
    """
    Create a signed JWT with an expiration to mitigate token reuse (CWE-284/CWE-863).
    """
    now = int(time.time())
    payload = {
        "sub": username,
        "uid": user_id,
        "iat": now,
        "exp": now + expires_in_seconds,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm="HS256")
    # PyJWT returns str in v2
    return token


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_security),
) -> Optional[str]:
    """
    Returns the username from a valid JWT bearer token.
    If invalid or missing, returns None. The endpoint should respond with 401 and a 'message' field.
    """
    if credentials is None or not credentials.scheme.lower() == "bearer":
        return None
    token = credentials.credentials
    try:
        data = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        username = data.get("sub")
        if not username:
            return None
        return username
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception:
        # Handle exceptional conditions generically (CWE-703)
        return None


# Global exception handler to avoid leaking internal errors (CWE-703)
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


@app.post(
    "/register",
    summary="User registration",
    description="Register a new user with email, username and password.",
    tags=["Authentication"],
)
async def register_user(payload: RegisterRequest):
    conn = None
    try:
        # Normalize input
        email = payload.email.strip().lower()
        username = payload.username.strip()
        password_hash = hash_password(payload.password)

        conn = get_db_connection()

        # Attempt to insert; rely on UNIQUE constraints to prevent duplicates
        try:
            conn.execute(
                "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?);",
                (email, username, password_hash),
            )
        except sqlite3.IntegrityError:
            # Email already in use or username taken
            return JSONResponse(
                status_code=400, content={"message": "Email already in use or invalid data"}
            )

        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except sqlite3.Error:
        # Database error handling
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    finally:
        if conn:
            conn.close()


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
    tags=["Authentication"],
)
async def login_user(payload: LoginRequest):
    conn = None
    try:
        email = payload.email.strip().lower()
        password = payload.password

        conn = get_db_connection()
        cur = conn.execute("SELECT id, username, password_hash FROM users WHERE email = ?;", (email,))
        row = cur.fetchone()
        if not row:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

        user_id = row["id"]
        username = row["username"]
        password_hash = row["password_hash"]

        if not verify_password(password, password_hash):
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

        token = create_access_token(username=username, user_id=user_id)
        return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})
    except sqlite3.Error:
        # Avoid leaking details
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
    finally:
        if conn:
            conn.close()


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
    dependencies=[Depends(bearer_security)],
)
async def set_secret(payload: SetSecretRequest, current_user: Optional[str] = Depends(get_current_user)):
    # Authorization: token must match provided username (CWE-284 / CWE-863)
    if current_user is None or current_user != payload.username:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    conn = None
    try:
        conn = get_db_connection()

        # Resolve user_id from username to avoid direct trust of client-sent identifiers
        cur = conn.execute("SELECT id FROM users WHERE username = ?;", (payload.username,))
        user_row = cur.fetchone()
        if not user_row:
            # Avoid user enumeration; treat as invalid token context
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

        user_id = user_row["id"]

        # Upsert secret securely using parameterized SQL (mitigates CWE-89)
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET
              secret = excluded.secret,
              updated_at = CURRENT_TIMESTAMP;
            """,
            (user_id, payload.secret),
        )

        return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})
    except sqlite3.Error:
        # Handle DB errors gracefully (CWE-703)
        return JSONResponse(status_code=500, content={"message": "Internal server error"})
    finally:
        if conn:
            conn.close()


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
    dependencies=[Depends(bearer_security)],
)
async def get_secret(
    username: str = Query(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$"),
    current_user: Optional[str] = Depends(get_current_user),
):
    if current_user is None or current_user != username:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    conn = None
    try:
        conn = get_db_connection()
        cur_user = conn.execute("SELECT id FROM users WHERE username = ?;", (username,))
        user_row = cur_user.fetchone()
        if not user_row:
            # Avoid user enumeration
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

        user_id = user_row["id"]

        cur_secret = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
        sec_row = cur_secret.fetchone()
        secret_value = sec_row["secret"] if sec_row else ""
        return JSONResponse(status_code=200, content={"secret": secret_value})
    except sqlite3.Error:
        return JSONResponse(status_code=500, content={"message": "Internal server error"})
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)