import os
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
import secrets as syssecrets
import re

from fastapi import FastAPI, HTTPException, Security, status, Request, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from email_validator import validate_email, EmailNotValidError
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn
from fastapi.openapi.utils import get_openapi


# ----------------------------
# Configuration and Logging
# ----------------------------

APP_NAME = "Secret Storage"
APP_DESC = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

DB_PATH = "db.sqlite3"

# Load application secret for JWT signing
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET or len(APP_SECRET.strip()) == 0:
    # Fallback to a strong random secret if not provided.
    # Note: For production, always set APP_SECRET via environment variable.
    APP_SECRET = syssecrets.token_urlsafe(64)

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(APP_NAME)


# ----------------------------
# Utility functions
# ----------------------------

def get_db_conn() -> sqlite3.Connection:
    """
    Create a new SQLite database connection for the current request.
    Ensures foreign key enforcement and Row factory for safer access.
    """
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    """
    Initialize database tables if they do not exist.
    Uses parameterized SQL to avoid SQL injection (CWE-89).
    """
    try:
        conn = get_db_conn()
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS secrets (
                    user_id INTEGER NOT NULL UNIQUE,
                    secret_value TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            """)
    except Exception as e:
        logger.exception("Database initialization failed: %s", e)
        # If DB init fails, raise a clear exception to avoid undefined state (CWE-703)
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass


def sanitize_username(username: str) -> str:
    """
    Validate username to prevent misuse and enforce a reasonable policy.
    """
    if username is None:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    username = username.strip()
    if len(username) < 3 or len(username) > 50:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    # Allow alphanumeric, underscore and hyphen only
    if not re.fullmatch(r"[A-Za-z0-9_-]+", username):
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    return username


def validate_email_str(email: str) -> str:
    """
    Validate email using email_validator package.
    """
    if email is None:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    email = email.strip()
    try:
        v = validate_email(email)
        return v.email
    except EmailNotValidError:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")


def validate_password(password: str) -> str:
    """
    Ensure password meets minimum strength requirements.
    """
    if password is None:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    password = password.strip()
    if len(password) < 8 or len(password) > 128:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    return password


def create_access_token(username: str, email: str) -> str:
    """
    Create a JWT access token with expiry and subject fields.
    """
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "email": email,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    """
    Decode a JWT token safely, raising appropriate HTTPException on failure.
    """
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")


# ----------------------------
# FastAPI app and security
# ----------------------------

app = FastAPI(title=APP_NAME, description=APP_DESC, version=APP_VERSION)

http_bearer = HTTPBearer(auto_error=False)


async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(http_bearer)) -> sqlite3.Row:
    """
    Dependency to get and validate current user from the Bearer token.
    Ensures proper authentication and authorization checks (CWE-284, CWE-863).
    """
    if credentials is None or not credentials.scheme.lower() == "bearer":
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    token = credentials.credentials
    payload = decode_token(token)
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    conn = get_db_conn()
    try:
        user = conn.execute("SELECT id, email, username FROM users WHERE username = ?", (username,)).fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        return user
    finally:
        conn.close()


# ----------------------------
# Pydantic models
# ----------------------------

class RegisterRequest(BaseModel):
    email: str = Field(..., example="newuser@example.com")
    username: str = Field(..., example="user1")
    password: str = Field(..., example="newUserPassword")


class RegisterResponse(BaseModel):
    message: str = Field(..., example="Registration successful")


class LoginRequest(BaseModel):
    email: str = Field(..., example="user1@example.com")
    password: str = Field(..., example="pass1")


class LoginResponse(BaseModel):
    token: str = Field(..., example="jwt-token-abc123")
    message: str = Field(..., example="Login successful")


class SetSecretRequest(BaseModel):
    username: str = Field(..., example="user1")
    secret: str = Field(..., example="mySecret")


class SetSecretResponse(BaseModel):
    message: str = Field(..., example="Secret has been set successfully")


class GetSecretResponse(BaseModel):
    secret: str = Field(..., example="The secret associated with the provided details")


# ----------------------------
# Exception handlers
# ----------------------------

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """
    Consistent error responses using {"message": "..."} format to match OpenAPI.
    """
    message = exc.detail if isinstance(exc.detail, str) else "An error occurred"
    return JSONResponse(status_code=exc.status_code, content={"message": message})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """
    Handle unexpected exceptions gracefully (CWE-703).
    """
    logger.exception("Unhandled exception: %s", exc)
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


# ----------------------------
# Routes
# ----------------------------

@app.on_event("startup")
def on_startup():
    init_db()
    logger.info("Application started with secure configuration.")


@app.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest):
    """
    Register a new user with email, username and password.
    """
    email = validate_email_str(payload.email)
    username = sanitize_username(payload.username)
    password = validate_password(payload.password)

    password_hash = pbkdf2_sha256.hash(password)
    now = datetime.now(timezone.utc).isoformat()

    conn = get_db_conn()
    try:
        with conn:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, username, password_hash, now),
            )
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Unique constraint violated or invalid data
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    finally:
        conn.close()


@app.post("/login", response_model=LoginResponse, status_code=status.HTTP_200_OK)
async def login(payload: LoginRequest):
    """
    Authenticate a user with email and password.
    """
    email = validate_email_str(payload.email)
    password = payload.password.strip()

    conn = get_db_conn()
    try:
        user = conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid email or password")
        stored_hash = user["password_hash"]
        if not pbkdf2_sha256.verify(password, stored_hash):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        token = create_access_token(username=user["username"], email=user["email"])
        return {"token": token, "message": "Login successful"}
    finally:
        conn.close()


@app.post("/set_secret", response_model=SetSecretResponse, status_code=status.HTTP_200_OK)
async def set_secret(payload: SetSecretRequest, current_user: sqlite3.Row = Security(get_current_user)):
    """
    Save a secret on the server using the username and the secret text.
    Requires a valid Bearer token; authorization checks ensure a user can only
    set their own secret (CWE-863).
    """
    # Ensure the user in token matches the provided username
    req_username = sanitize_username(payload.username)
    if current_user["username"] != req_username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    secret_text = payload.secret.strip()
    now = datetime.now(timezone.utc).isoformat()

    conn = get_db_conn()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO secrets (user_id, secret_value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret_value=excluded.secret_value,
                    updated_at=excluded.updated_at
                """,
                (current_user["id"], secret_text, now),
            )
        return {"message": "Secret has been set successfully"}
    finally:
        conn.close()


@app.get("/get_secret", response_model=GetSecretResponse, status_code=status.HTTP_200_OK)
async def get_secret(username: str = Query(..., example="user1"), current_user: sqlite3.Row = Security(get_current_user)):
    """
    Retrieve a secret based on the provided username.
    Requires a valid Bearer token; authorization checks ensure a user can only
    retrieve their own secret (CWE-284, CWE-863).
    """
    req_username = sanitize_username(username)
    if current_user["username"] != req_username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    conn = get_db_conn()
    try:
        row = conn.execute(
            "SELECT secret_value FROM secrets WHERE user_id = ?",
            (current_user["id"],),
        ).fetchone()
        if not row:
            # No secret set yet; return empty string to match schema with 200 response
            return {"secret": ""}
        return {"secret": row["secret_value"]}
    finally:
        conn.close()


# ----------------------------
# Custom OpenAPI to match the provided schema
# ----------------------------

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=APP_NAME,
        version=APP_VERSION,
        description=APP_DESC,
        routes=app.routes,
    )

    # Define bearerAuth scheme as required
    components = openapi_schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }

    # Set global security requirement
    openapi_schema["security"] = [{"bearerAuth": []}]

    # Override /register and /login to have empty security (as per provided schema)
    try:
        register_post = openapi_schema["paths"]["/register"]["post"]
        register_post["security"] = []
        register_post["summary"] = "User registration"
        register_post["description"] = "Register a new user with email, username and password."
        # Examples
        req_body = register_post.get("requestBody", {}).get("content", {}).get("application/json", {})
        if req_body is not None:
            req_body["examples"] = {
                "newUser": {
                    "summary": "Sample new user",
                    "value": {
                        "email": "newuser@example.com",
                        "username": "user1",
                        "password": "newUserPassword",
                    },
                }
            }
        # Responses examples/messages
        responses = register_post.get("responses", {})
        if "201" in responses:
            responses["201"]["content"]["application/json"]["schema"] = {
                "type": "object",
                "properties": {"message": {"type": "string", "example": "Registration successful"}},
            }
        responses["400"] = {
            "description": "Bad Request",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {"message": {"type": "string", "example": "Email already in use or invalid data"}},
                    }
                }
            },
        }
    except Exception:
        pass

    try:
        login_post = openapi_schema["paths"]["/login"]["post"]
        login_post["security"] = []
        login_post["summary"] = "User login"
        login_post["description"] = "Authenticate a user with email and password."
        req_body = login_post.get("requestBody", {}).get("content", {}).get("application/json", {})
        if req_body is not None:
            req_body["examples"] = {
                "user1": {
                    "summary": "Sample user #1",
                    "value": {"email": "user1@example.com", "password": "pass1"},
                }
            }
        responses = login_post.get("responses", {})
        if "200" in responses:
            responses["200"]["content"]["application/json"]["schema"] = {
                "type": "object",
                "properties": {
                    "token": {"type": "string", "example": "jwt-token-abc123"},
                    "message": {"type": "string", "example": "Login successful"},
                },
            }
        responses["401"] = {
            "description": "Unauthorized",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {"message": {"type": "string", "example": "Invalid email or password"}},
                    }
                }
            },
        }
    except Exception:
        pass

    try:
        set_secret_post = openapi_schema["paths"]["/set_secret"]["post"]
        set_secret_post["summary"] = "Set secret"
        set_secret_post["description"] = "Save a secret on the server using the username, token, and the secret text."
        req_body = set_secret_post.get("requestBody", {}).get("content", {}).get("application/json", {})
        if req_body is not None:
            req_body["examples"] = {
                "example1": {
                    "summary": "Set a secret for user1",
                    "value": {"username": "user1", "secret": "mySecret"},
                }
            }
        responses = set_secret_post.get("responses", {})
        if "200" in responses:
            responses["200"]["content"]["application/json"]["schema"] = {
                "type": "object",
                "properties": {"message": {"type": "string", "example": "Secret has been set successfully"}},
            }
        responses["401"] = {
            "description": "Unauthorized",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {"message": {"type": "string", "example": "Invalid authentication token"}},
                    }
                }
            },
        }
    except Exception:
        pass

    try:
        get_secret_get = openapi_schema["paths"]["/get_secret"]["get"]
        get_secret_get["summary"] = "Get secret"
        get_secret_get["description"] = "Retrieve a secret based on the provided username."
        responses = get_secret_get.get("responses", {})
        if "200" in responses:
            responses["200"]["content"]["application/json"]["schema"] = {
                "type": "object",
                "properties": {"secret": {"type": "string", "example": "The secret associated with the provided details"}},
            }
        responses["401"] = {
            "description": "Unauthorized",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {"message": {"type": "string", "example": "Invalid authentication token"}},
                    }
                }
            },
        }
    except Exception:
        pass

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# ----------------------------
# Entrypoint
# ----------------------------

if __name__ == "__main__":
    # Start the webserver at 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)