import os
import sqlite3
import hmac
import hashlib
import base64
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr, ValidationError
import jwt  # pyjwt
import uvicorn

DB_PATH = "db.sqlite3"
JWT_ALGORITHM = "HS256"
# Load application secret used for signing JWTs. If not provided, generate a random one.
APP_SECRET = os.environ.get("APP_SECRET") or base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")

# ==========================
# Database Utilities
# ==========================

def get_db():
    """
    Opens a new database connection per request and ensures foreign keys are enforced.
    """
    conn = sqlite3.connect(DB_PATH, isolation_level=None, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def init_db():
    """
    Initialize database schema safely.
    """
    conn = sqlite3.connect(DB_PATH, isolation_level=None, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL
            );

            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER PRIMARY KEY,
                secret TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        # Defensive indices (unique constraints already exist)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
    finally:
        conn.close()


# ==========================
# Security Utilities
# ==========================

def _pbkdf2(password: str, salt: bytes, iterations: int = 200_000, dklen: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=dklen)


def hash_password(password: str) -> str:
    """
    Derive a secure hash using PBKDF2-HMAC-SHA256 with a random salt.
    Stored format: pbkdf2_sha256$iterations$salt_hex$hash_hex
    """
    iterations = 200_000
    salt = secrets.token_bytes(16)
    dk = _pbkdf2(password, salt, iterations=iterations, dklen=32)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """
    Verify a password against the stored PBKDF2 hash.
    """
    try:
        scheme, iters_str, salt_hex, hash_hex = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(iters_str)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        candidate = _pbkdf2(password, salt, iterations=iterations, dklen=len(expected))
        return hmac.compare_digest(candidate, expected)
    except Exception:
        # Any parsing or computation error should result in failure without leaking details
        return False


def create_access_token(username: str, ttl_minutes: int = 60) -> str:
    """
    Create a JWT access token for a given username with expiration.
    """
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": username,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ttl_minutes)).timestamp()),
        "jti": str(uuid.uuid4()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    # pyjwt returns str in v2
    return token


def decode_access_token(token: str) -> dict:
    """
    Decode and validate a JWT. Raises jwt exceptions if invalid/expired.
    """
    return jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])


# ==========================
# Pydantic Models
# ==========================

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_]+$", example="user1")
    password: str = Field(..., min_length=8, max_length=128, example="newUserPassword")


class MessageResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: str = Field(..., min_length=8, max_length=128, example="pass1")


class LoginResponse(BaseModel):
    token: str
    message: str


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_]+$", example="user1")
    secret: str = Field(..., min_length=0, max_length=8192, example="mySecret")


class SetSecretResponse(BaseModel):
    message: str


class GetSecretResponse(BaseModel):
    secret: str


# ==========================
# FastAPI App and Security
# ==========================

app = FastAPI(
    title="Secret Storage",
    version="1.0.0",
    description="A secure cloud storage app for string secrets.",
    openapi_tags=[
        {"name": "Authentication", "description": "Operations related to user authentication"},
    ],
)

security = HTTPBearer(auto_error=False)


def unauthorized_token_response() -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid authentication token"})


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: sqlite3.Connection = Depends(get_db),
):
    """
    Validates the Authorization header and returns the user row.
    """
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        # Missing or invalid scheme
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    token = credentials.credentials
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    try:
        payload = decode_access_token(token)
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        # Normalize
        username_norm = username.strip().lower()
        user = db.execute("SELECT id, email, username FROM users WHERE username = ?", (username_norm,)).fetchone()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except Exception:
        # Any unexpected error should not leak details
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


@app.on_event("startup")
def on_startup():
    try:
        init_db()
    except Exception:
        # If DB initialization fails, raise a fatal error
        raise


# ==========================
# Routes
# ==========================

@app.post(
    "/register",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
    openapi_extra={"security": []},
)
def register(req: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    """
    Register a new user with email, username, and password.
    """
    try:
        email_norm = req.email.strip().lower()
        username_norm = req.username.strip().lower()

        # Basic additional validation
        if len(username_norm) < 3 or len(username_norm) > 50:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )
        if len(req.password) < 8 or len(req.password) > 128:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )

        password_hash = hash_password(req.password)
        now = datetime.now(tz=timezone.utc)

        db.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email_norm, username_norm, password_hash, now),
        )

        return JSONResponse(status_code=status.HTTP_201_CREATED, content={"message": "Registration successful"})
    except sqlite3.IntegrityError:
        # Email or username already exists
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )
    except Exception:
        # Generic safe error message (CWE-703)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )


@app.post(
    "/login",
    response_model=LoginResponse,
    tags=["Authentication"],
    openapi_extra={"security": []},
)
def login(req: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    """
    Authenticate a user with email and password, return JWT.
    """
    try:
        email_norm = req.email.strip().lower()
        user = db.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (email_norm,),
        ).fetchone()
        if not user:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"}
            )
        if not verify_password(req.password, user["password_hash"]):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"}
            )

        token = create_access_token(username=user["username"])
        return {"token": token, "message": "Login successful"}
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"}
        )


@app.post(
    "/set_secret",
    response_model=SetSecretResponse,
)
def set_secret(
    req: SetSecretRequest,
    current_user=Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    """
    Save a secret on the server using the username, token, and the secret text.
    Requires valid Bearer token and the username in the body must match the token subject.
    """
    try:
        # Authorization check (CWE-284, CWE-863)
        body_username = req.username.strip().lower()
        token_username = (current_user["username"] or "").strip().lower()
        if body_username != token_username:
            # Do not leak that the token might belong to a different user; keep generic message
            return unauthorized_token_response()

        # Upsert secret for this user
        user_id = current_user["id"]
        # Use an UPSERT pattern securely (CWE-89)
        db.execute(
            """
            INSERT INTO secrets (user_id, secret) VALUES (?, ?)
            ON CONFLICT(user_id) DO UPDATE SET secret = excluded.secret
            """,
            (user_id, req.secret),
        )

        return {"message": "Secret has been set successfully"}
    except Exception:
        # Generic error path
        return unauthorized_token_response()


@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
)
def get_secret(
    username: str,
    current_user=Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    """
    Retrieve a secret based on the provided username. Requires a valid Bearer token
    and the username must match the token subject.
    """
    try:
        query_username = (username or "").strip().lower()
        token_username = (current_user["username"] or "").strip().lower()
        if query_username != token_username:
            return unauthorized_token_response()

        # Fetch secret
        user_id = current_user["id"]
        row = db.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,)).fetchone()
        secret_value = row["secret"] if row and row["secret"] is not None else ""
        return {"secret": secret_value}
    except Exception:
        return unauthorized_token_response()


# ==========================
# OpenAPI Customization to reflect security schemes
# ==========================

from fastapi.openapi.utils import get_openapi

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    # Security scheme
    components = schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Global security requirement
    schema["security"] = [{"bearerAuth": []}]
    # Clear security for /register and /login
    paths = schema.get("paths", {})
    for p in ("/register", "/login"):
        if p in paths:
            for method in paths[p].values():
                if isinstance(method, dict):
                    method["security"] = []
    app.openapi_schema = schema
    return app.openapi_schema

app.openapi = custom_openapi


# ==========================
# Run Server
# ==========================

if __name__ == "__main__":
    # Ensure DB is initialized before starting (in case startup event timing differs)
    try:
        init_db()
    except Exception:
        # If DB can't init, exit gracefully
        raise
    uvicorn.run(app, host="0.0.0.0", port=5000)