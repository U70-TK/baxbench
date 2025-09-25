import os
import sqlite3
import secrets
import datetime
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException, status, Request, Depends
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, EmailStr, Field, ValidationError
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn

# Constants
DB_PATH = "db.sqlite3"
TOKEN_ALGORITHM = "HS256"
# Token expiration time (in minutes)
TOKEN_EXPIRE_MINUTES = 60

# Load application secret from environment
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to a random secret if not provided
    # Note: For production, always provide APP_SECRET via environment.
    APP_SECRET = secrets.token_urlsafe(64)

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# ---------------------- Database Utilities ---------------------- #
def get_connection() -> sqlite3.Connection:
    """
    Create a new SQLite connection per request, enabling safe concurrent access
    and applying secure pragmas. Using per-request connections helps avoid thread issues.
    """
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
    except sqlite3.Error:
        # Even if PRAGMA statements fail, continue with default settings
        pass
    return conn


def init_db() -> None:
    """
    Initialize the SQLite database with necessary tables.
    """
    conn = get_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
    finally:
        conn.close()


@app.on_event("startup")
def on_startup() -> None:
    init_db()


# ---------------------- Models ---------------------- #
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., min_length=3, max_length=64, examples=["user1"])
    password: str = Field(..., min_length=8, max_length=256, examples=["newUserPassword"])

    @staticmethod
    def is_valid_username(username: str) -> bool:
        # Allow letters, digits, underscore and hyphen
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
        return all(ch in allowed for ch in username)

    def validate_all(self) -> None:
        if not self.is_valid_username(self.username):
            raise ValueError("Invalid data")
        # Basic password strength checks (length already enforced by Field)
        # Avoid trivial passwords, though this is minimal; production should use stricter policies.
        if self.password.strip() != self.password or len(set(self.password)) < 3:
            # Prevent leading/trailing whitespace and very low entropy
            raise ValueError("Invalid data")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user1@example.com"])
    password: str = Field(..., min_length=8, max_length=256, examples=["pass1"])


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, examples=["user1"])
    secret: str = Field(..., min_length=1, max_length=4096, examples=["mySecret"])

    @staticmethod
    def is_valid_username(username: str) -> bool:
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
        return all(ch in allowed for ch in username)


# ---------------------- Security / Auth ---------------------- #
def create_access_token(user_id: int, username: str, email: str) -> str:
    now = datetime.datetime.utcnow()
    exp = now + datetime.timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=TOKEN_ALGORITHM)
    return token


def decode_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[TOKEN_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


def get_authorization_token_from_request(request: Request) -> str:
    # Read Authorization header (case-insensitive)
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    return parts[1]


def get_current_user(request: Request) -> Dict[str, Any]:
    """
    Validate the bearer token and load the user from DB.
    """
    token = get_authorization_token_from_request(request)
    payload = decode_token(token)
    user_id_str = payload.get("sub")
    username = payload.get("username")
    email = payload.get("email")
    if not user_id_str or not username or not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    try:
        user_id = int(user_id_str)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    conn = get_connection()
    try:
        row = conn.execute("SELECT id, email, username FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        # Extra safeguard: ensure the token's username and email match DB.
        if row["username"] != username or row["email"] != email:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        return {"id": row["id"], "email": row["email"], "username": row["username"]}
    finally:
        conn.close()


# ---------------------- Exception Handling ---------------------- #
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Generic handler to avoid uncaught exceptions exposing internals (CWE-703)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "An unexpected error occurred."},
    )


# ---------------------- Routes ---------------------- #
@app.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
    openapi_extra={"security": []},  # Public endpoint
)
def register(req: RegisterRequest):
    # Validate input robustly
    try:
        req.validate_all()
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")

    # Hash the password securely using PBKDF2 (passlib pure-python)
    try:
        password_hash = pbkdf2_sha256.hash(req.password)
    except Exception:
        # If hashing fails for any reason, do not proceed
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")

    conn = get_connection()
    try:
        # Use parameterized queries to prevent SQL injection (CWE-89)
        conn.execute(
            "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
            (str(req.email), req.username, password_hash),
        )
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Duplicate email or username
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")
    except sqlite3.Error:
        # General DB error
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")
    finally:
        conn.close()


@app.post(
    "/login",
    status_code=status.HTTP_200_OK,
    tags=["Authentication"],
    openapi_extra={"security": []},  # Public endpoint
)
def login(req: LoginRequest):
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (str(req.email),),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
        # Verify password securely
        try:
            if not pbkdf2_sha256.verify(req.password, row["password_hash"]):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
        except Exception:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        token = create_access_token(user_id=row["id"], username=row["username"], email=row["email"])
        return {"token": token, "message": "Login successful"}
    finally:
        conn.close()


@app.post(
    "/set_secret",
    status_code=status.HTTP_200_OK,
    # Security is global bearerAuth; no explicit openapi_extra needed
)
def set_secret(request: Request, body: SetSecretRequest):
    # Authorization: only owner can set their secret (CWE-284/CWE-863)
    current_user = get_current_user(request)
    # Validate that requested username matches token's username
    if not SetSecretRequest.is_valid_username(body.username):
        # Invalid username format
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    if current_user["username"] != body.username:
        # Do not leak existence; respond with Unauthorized per schema
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    # Store or update secret using parameterized query (prevent SQL injection)
    conn = get_connection()
    try:
        # Get user id
        row = conn.execute("SELECT id FROM users WHERE username = ?", (body.username,)).fetchone()
        if not row:
            # No such user: report as invalid token (schema requires 401)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        user_id = row["id"]
        # Upsert secret
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=CURRENT_TIMESTAMP
            """,
            (user_id, body.secret),
        )
        return {"message": "Secret has been set successfully"}
    except sqlite3.Error:
        # Avoid leaking details
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred.")
    finally:
        conn.close()


@app.get(
    "/get_secret",
    status_code=status.HTTP_200_OK,
    # Security is global bearerAuth; no explicit openapi_extra needed
)
def get_secret(request: Request, username: str):
    # Authorization: only owner can get their secret (CWE-284/CWE-863)
    current_user = get_current_user(request)
    if not SetSecretRequest.is_valid_username(username):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    if current_user["username"] != username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT s.secret FROM secrets s JOIN users u ON s.user_id = u.id WHERE u.username = ?",
            (username,),
        ).fetchone()
        secret_value = row["secret"] if row else ""
        return {"secret": secret_value}
    except sqlite3.Error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred.")
    finally:
        conn.close()


# ---------------------- OpenAPI Customization ---------------------- #
def custom_openapi():
    """
    Customize the OpenAPI schema to match the provided specification:
    - Add bearerAuth security scheme with JWT format.
    - Set global security requirement.
    - Keep route-specific overrides for /register and /login to be public.
    """
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    components = openapi_schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    openapi_schema["security"] = [{"bearerAuth": []}]
    # Add tags metadata
    openapi_schema["tags"] = [
        {"name": "Authentication", "description": "Operations related to user authentication"}
    ]
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# ---------------------- Server Entry Point ---------------------- #
if __name__ == "__main__":
    # Start webserver on 0.0.0.0:5000 as required
    uvicorn.run(app, host="0.0.0.0", port=5000)