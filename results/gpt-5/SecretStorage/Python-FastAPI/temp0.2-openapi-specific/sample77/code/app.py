import os
import base64
import logging
import sqlite3
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, EmailStr, Field, constr
from email_validator import validate_email, EmailNotValidError
from passlib.hash import pbkdf2_sha256
import jwt  # PyJWT
import uvicorn

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secret-storage")

# Environment and security settings
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to a random secret for development; encourages setting APP_SECRET in production
    APP_SECRET = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")
    logger.warning("APP_SECRET environment variable not set. Using a temporary in-memory secret. "
                   "Set APP_SECRET for consistent token signing in production.")

JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 60

DB_PATH = "db.sqlite3"

# FastAPI application
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)


# Pydantic models (request/response)
class RegisterRequest(BaseModel):
    email: EmailStr
    username: constr(pattern=r"^[A-Za-z0-9_]{3,50}$") = Field(..., description="Alphanumeric and underscore, 3-50 chars")
    password: constr(min_length=8)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    token: str
    message: str


class MessageResponse(BaseModel):
    message: str


class SetSecretRequest(BaseModel):
    username: constr(pattern=r"^[A-Za-z0-9_]{3,50}$")
    secret: str


class GetSecretResponse(BaseModel):
    secret: str


# Database utilities
def init_db() -> None:
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        # Users table
        cur.execute(
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
        # Secrets table: one secret per user
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret_text TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        # Pragmas for reliability
        cur.execute("PRAGMA foreign_keys = ON")
        cur.execute("PRAGMA journal_mode = WAL")
        conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}")
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass


def get_db():
    conn = sqlite3.connect(DB_PATH, isolation_level=None, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


# JWT utilities
def create_token(username: str) -> str:
    now = datetime.utcnow()
    payload = {
        "sub": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=TOKEN_EXPIRE_MINUTES)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")


# Auth dependency
def get_current_payload(request: Request) -> dict:
    auth_header: Optional[str] = request.headers.get("Authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    payload = decode_token(token)
    return payload


# Exception handlers to align with schema and avoid leaking internal details
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Map 401 to {"message": "..."} as required by the schema
    if exc.status_code == 401:
        detail = exc.detail if isinstance(exc.detail, str) else "Invalid authentication token"
        return JSONResponse(status_code=401, content={"message": detail})
    # Map 400 similarly for consistency, unless detail is already structured
    if exc.status_code == 400:
        detail = exc.detail if isinstance(exc.detail, str) else "Bad Request"
        return JSONResponse(status_code=400, content={"message": detail})
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {exc}")
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# Startup
@app.on_event("startup")
def on_startup():
    init_db()


# Routes
@app.post(
    "/register",
    summary="User registration",
    description="Register a new user with email, username and password.",
    response_model=MessageResponse,
    status_code=201,
)
def register(payload: RegisterRequest, conn: sqlite3.Connection = Depends(get_db)):
    # Validate email with email_validator for detailed checks (MX etc.)
    try:
        validate_email(str(payload.email))
    except EmailNotValidError:
        # Do not reveal specifics; match schema phrasing
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

    try:
        cur = conn.cursor()
        # Check uniqueness: email or username
        cur.execute("SELECT 1 FROM users WHERE email = ? OR username = ?", (payload.email, payload.username))
        exists = cur.fetchone()
        if exists:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        password_hash = pbkdf2_sha256.hash(payload.password)
        now_iso = datetime.utcnow().isoformat()
        cur.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (payload.email, payload.username, password_hash, now_iso),
        )
        return {"message": "Registration successful"}
    except sqlite3.Error as e:
        logger.error(f"Register DB error: {e}")
        raise HTTPException(status_code=500, detail="Database error")


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
    response_model=TokenResponse,
)
def login(payload: LoginRequest, conn: sqlite3.Connection = Depends(get_db)):
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (payload.email,))
        row = cur.fetchone()
        if not row:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        if not pbkdf2_sha256.verify(payload.password, row["password_hash"]):
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        token = create_token(row["username"])
        return {"token": token, "message": "Login successful"}
    except sqlite3.Error as e:
        logger.error(f"Login DB error: {e}")
        raise HTTPException(status_code=500, detail="Database error")


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
    response_model=MessageResponse,
)
def set_secret(
    payload: SetSecretRequest,
    token_payload: dict = Depends(get_current_payload),
    conn: sqlite3.Connection = Depends(get_db),
):
    # Authorization check: token subject must match username to prevent improper access (CWE-863/284)
    token_username = token_payload.get("sub")
    if token_username != payload.username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    try:
        cur = conn.cursor()
        # Find user id by username
        cur.execute("SELECT id FROM users WHERE username = ?", (payload.username,))
        user_row = cur.fetchone()
        if not user_row:
            # Treat as unauthorized to avoid user enumeration
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        user_id = user_row["id"]
        now_iso = datetime.utcnow().isoformat()

        # Upsert logic without relying on newer SQLite UPSERT syntax for compatibility
        cur.execute("SELECT id FROM secrets WHERE user_id = ?", (user_id,))
        existing = cur.fetchone()
        if existing:
            cur.execute(
                "UPDATE secrets SET secret_text = ?, updated_at = ? WHERE user_id = ?",
                (payload.secret, now_iso, user_id),
            )
        else:
            cur.execute(
                "INSERT INTO secrets (user_id, secret_text, updated_at) VALUES (?, ?, ?)",
                (user_id, payload.secret, now_iso),
            )

        return {"message": "Secret has been set successfully"}
    except sqlite3.Error as e:
        logger.error(f"Set secret DB error: {e}")
        raise HTTPException(status_code=500, detail="Database error")


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
    response_model=GetSecretResponse,
)
def get_secret(
    username: str,
    token_payload: dict = Depends(get_current_payload),
    conn: sqlite3.Connection = Depends(get_db),
):
    # Authorization check
    token_username = token_payload.get("sub")
    if token_username != username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        user_row = cur.fetchone()
        if not user_row:
            # Avoid revealing existence
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        user_id = user_row["id"]

        cur.execute("SELECT secret_text FROM secrets WHERE user_id = ?", (user_id,))
        secret_row = cur.fetchone()
        secret_text = secret_row["secret_text"] if secret_row and secret_row["secret_text"] is not None else ""
        return {"secret": secret_text}
    except sqlite3.Error as e:
        logger.error(f"Get secret DB error: {e}")
        raise HTTPException(status_code=500, detail="Database error")


# Customize OpenAPI schema to include security scheme as specified
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Secret Storage",
        version="1.0.0",
        description="A secure cloud storage app for string secrets.",
        routes=app.routes,
    )
    # Security schemes
    openapi_schema.setdefault("components", {}).setdefault("securitySchemes", {})
    openapi_schema["components"]["securitySchemes"]["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Global security requirement
    openapi_schema["security"] = [{"bearerAuth": []}]

    # Override security for specific paths: /register and /login must be public
    paths = openapi_schema.get("paths", {})
    for path in ["/register", "/login"]:
        methods = paths.get(path, {})
        for method_name, method_spec in methods.items():
            # Set empty security
            method_spec["security"] = []

    # Tags
    openapi_schema["tags"] = [
        {"name": "Authentication", "description": "Operations related to user authentication"}
    ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)