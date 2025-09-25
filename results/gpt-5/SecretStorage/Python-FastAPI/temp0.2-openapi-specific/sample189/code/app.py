import os
import sqlite3
import secrets as std_secrets
from datetime import datetime, timedelta
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, status, Security, Query, Body
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, EmailStr, Field, constr
from starlette.responses import JSONResponse
from passlib.context import CryptContext
import jwt


# Application configuration
APP_SECRET = os.getenv("APP_SECRET") or std_secrets.token_urlsafe(32)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Initialize FastAPI app
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Security scheme
bearer_scheme = HTTPBearer(auto_error=False)

# Password hashing context
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


# Database utilities
DB_PATH = "db.sqlite3"


def get_db_connection() -> sqlite3.Connection:
    """
    Create a new SQLite3 connection with safe settings.
    Returns a connection that enforces foreign keys and uses Row factory.
    """
    try:
        conn = sqlite3.connect(DB_PATH, isolation_level=None)
        conn.row_factory = sqlite3.Row
        # Enforce foreign key constraints
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn
    except sqlite3.Error:
        # Handle rare DB connection issues robustly (CWE-703)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database connection error",
        )


def init_db():
    """Initialize the database schema if it doesn't exist."""
    conn = get_db_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
    except sqlite3.Error:
        # Handle schema creation issues robustly (CWE-703)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initialize database",
        )
    finally:
        conn.close()


# Models
class RegisterRequest(BaseModel):
    email: EmailStr = Field(
        ...,
        example="newuser@example.com",
        description="Valid email address",
    )
    username: constr(strip_whitespace=True, min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_\-]+$") = Field(
        ...,
        example="user1",
        description="Alphanumeric, underscores and hyphens; 3-32 chars",
    )
    password: constr(min_length=8) = Field(
        ...,
        example="newUserPassword",
        description="Minimum 8 characters",
    )


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user1@example.com")
    password: constr(min_length=8) = Field(..., example="mySecretPassword")


class SetSecretRequest(BaseModel):
    username: constr(strip_whitespace=True, min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_\-]+$") = Field(
        ...,
        example="user1",
    )
    secret: str = Field(..., example="mySecret")


# Helper functions
def hash_password(password: str) -> str:
    """Securely hash the password (CWE-522)."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash (CWE-522)."""
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False


def create_access_token(*, username: str, email: str, user_id: int, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode = {
        "sub": username,
        "uid": user_id,
        "email": email,
        "iat": datetime.utcnow(),
        "exp": expire,
    }
    token = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    """Retrieve user by email using parameterized query (CWE-89)."""
    try:
        cur = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
        return cur.fetchone()
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    """Retrieve user by username using parameterized query (CWE-89)."""
    try:
        cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cur.fetchone()
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


def create_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> int:
    """Create a new user; ensures unique constraints; parameterized (CWE-89)."""
    try:
        cur = conn.execute(
            "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
            (email, username, password_hash),
        )
        return cur.lastrowid
    except sqlite3.IntegrityError:
        # Email or username already exists
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


def set_secret_for_user(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    """Set or update the secret for a user using safe SQL (CWE-89)."""
    try:
        # Try update first
        cur = conn.execute(
            "UPDATE secrets SET secret = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
            (secret, user_id),
        )
        if cur.rowcount == 0:
            conn.execute(
                "INSERT INTO secrets (user_id, secret) VALUES (?, ?)",
                (user_id, secret),
            )
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


def get_secret_for_user(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    """Retrieve secret for user."""
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        return row["secret"] if row else None
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# Authorization dependency
def get_current_user(credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)) -> sqlite3.Row:
    """
    Decode and validate JWT and return the associated user row.
    Properly handles invalid/missing tokens (CWE-284/CWE-863).
    """
    if credentials is None or not credentials.scheme.lower() == "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    token = credentials.credentials
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        user_id = payload.get("uid")
        email = payload.get("email")
        if not username or not user_id or not email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
            )
        conn = get_db_connection()
        try:
            user = get_user_by_username(conn, username)
            if not user or user["id"] != user_id or user["email"] != email:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication token",
                )
            return user
        finally:
            conn.close()
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )


# Routes
@app.post(
    "/register",
    tags=["Authentication"],
    summary="User registration",
    description="Register a new user with email, username and password.",
    status_code=status.HTTP_201_CREATED,
)
def register(body: RegisterRequest = Body(
    ...,
    examples={
        "newUser": {
            "summary": "Sample new user",
            "value": {
                "email": "newuser@example.com",
                "username": "user1",
                "password": "newUserPassword",
            },
        }
    },
)):
    # Basic validations beyond pydantic can be added here (CWE-703)
    conn = get_db_connection()
    try:
        # Check duplicates explicitly to return friendly 400 before insert
        existing_email = get_user_by_email(conn, body.email)
        if existing_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use or invalid data",
            )
        existing_username = get_user_by_username(conn, body.username)
        if existing_username:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use or invalid data",
            )

        password_hash = hash_password(body.password)
        create_user(conn, body.email, body.username, password_hash)

        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"message": "Registration successful"},
        )
    finally:
        conn.close()


@app.post(
    "/login",
    tags=["Authentication"],
    summary="User login",
    description="Authenticate a user with email and password.",
)
def login(body: LoginRequest = Body(
    ...,
    examples={
        "user1": {
            "summary": "Sample user #1",
            "value": {
                "email": "user1@example.com",
                "password": "pass1",
            },
        }
    },
)):
    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, body.email)
        if not user or not verify_password(body.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )

        token = create_access_token(
            username=user["username"], email=user["email"], user_id=user["id"]
        )
        return {"token": token, "message": "Login successful"}
    finally:
        conn.close()


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(
    body: SetSecretRequest = Body(
        ...,
        examples={
            "example1": {
                "summary": "Set a secret for user1",
                "value": {"username": "user1", "secret": "mySecret"},
            }
        },
    ),
    current_user: sqlite3.Row = Security(get_current_user),
):
    # Authorization check: ensure token subject matches username (CWE-863)
    if current_user["username"] != body.username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    conn = get_db_connection()
    try:
        set_secret_for_user(conn, current_user["id"], body.secret)
        return {"message": "Secret has been set successfully"}
    finally:
        conn.close()


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(
    username: str = Query(..., example="user1"),
    current_user: sqlite3.Row = Security(get_current_user),
):
    # Authorization check (CWE-284/CWE-863)
    if current_user["username"] != username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    conn = get_db_connection()
    try:
        secret = get_secret_for_user(conn, current_user["id"])
        # Return empty string if not set to match schema (always returns 'secret')
        return {"secret": secret or ""}
    finally:
        conn.close()


# Customize OpenAPI schema to match the provided specification closely
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    # Ensure security schemes and global security requirement
    components = openapi_schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    openapi_schema["security"] = [{"bearerAuth": []}]

    # Remove security for register and login as per spec
    paths = openapi_schema.get("paths", {})
    if "/register" in paths and "post" in paths["/register"]:
        paths["/register"]["post"]["security"] = []
        # Responses override to match examples
        paths["/register"]["post"]["responses"] = {
            "201": {
                "description": "Successful registration",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {"message": {"type": "string", "example": "Registration successful"}},
                        }
                    }
                },
            },
            "400": {
                "description": "Bad Request",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {"message": {"type": "string", "example": "Email already in use or invalid data"}},
                        }
                    }
                },
            },
        }
    if "/login" in paths and "post" in paths["/login"]:
        paths["/login"]["post"]["security"] = []
        paths["/login"]["post"]["responses"] = {
            "200": {
                "description": "Successful login",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "token": {"type": "string", "example": "jwt-token-abc123"},
                                "message": {"type": "string", "example": "Login successful"},
                            },
                        }
                    }
                },
            },
            "401": {
                "description": "Unauthorized",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {"message": {"type": "string", "example": "Invalid email or password"}},
                        }
                    }
                },
            },
        }
    # set_secret and get_secret responses per spec
    if "/set_secret" in paths and "post" in paths["/set_secret"]:
        paths["/set_secret"]["post"]["responses"] = {
            "200": {
                "description": "Secret set successfully",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {"message": {"type": "string", "example": "Secret has been set successfully"}},
                        }
                    }
                },
            },
            "401": {
                "description": "Unauthorized",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {"message": {"type": "string", "example": "Invalid authentication token"}},
                        }
                    }
                },
            },
        }
    if "/get_secret" in paths and "get" in paths["/get_secret"]:
        paths["/get_secret"]["get"]["responses"] = {
            "200": {
                "description": "Secret retrieved successfully",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {"secret": {"type": "string", "example": "The secret associated with the provided details"}},
                        }
                    }
                },
            },
            "401": {
                "description": "Unauthorized",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {"message": {"type": "string", "example": "Invalid authentication token"}},
                        }
                    }
                },
            },
        }

    # Tags
    openapi_schema["tags"] = [{"name": "Authentication", "description": "Operations related to user authentication"}]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# Startup initialization
@app.on_event("startup")
def on_startup():
    init_db()


if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)