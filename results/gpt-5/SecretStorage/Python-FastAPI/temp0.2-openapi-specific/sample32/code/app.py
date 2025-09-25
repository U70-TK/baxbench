import os
import base64
import sqlite3
from typing import Generator, Optional
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, constr
from passlib.hash import pbkdf2_sha256
import jwt  # PyJWT


# App configuration
APP_TITLE = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

# Read application secret from environment or generate a secure ephemeral one
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate a secure random secret for runtime if not provided
    # Note: For production, you should provide APP_SECRET via environment variables.
    APP_SECRET = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DB_PATH = "db.sqlite3"


# FastAPI app
app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    openapi_tags=[{"name": "Authentication", "description": "Operations related to user authentication"}],
)


# Security scheme
security_scheme = HTTPBearer(auto_error=True)


# Pydantic models
class RegisterRequest(BaseModel):
    email: EmailStr
    username: constr(regex=r"^[A-Za-z0-9_]{3,32}$") = Field(..., description="Alphanumeric and underscore, 3-32 chars")
    password: constr(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=8, max_length=128)


class SetSecretRequest(BaseModel):
    username: constr(regex=r"^[A-Za-z0-9_]{3,32}$")
    secret: constr(min_length=1, max_length=4096)


# Database helpers
def init_db() -> None:
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA foreign_keys=ON")
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
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        conn.commit()
    except Exception as e:
        # Fatal error during DB init
        raise RuntimeError(f"Database initialization failed: {e}") from e
    finally:
        try:
            conn.close()
        except Exception:
            pass


def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
    finally:
        try:
            conn.commit()
        except Exception:
            # Best effort rollback if commit fails
            try:
                conn.rollback()
            except Exception:
                pass
        try:
            conn.close()
        except Exception:
            pass


# JWT helpers
def create_access_token(*, username: str, uid: int, email: str, expires_delta: Optional[timedelta] = None) -> str:
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    now = datetime.now(timezone.utc)
    to_encode = {
        "sub": username,
        "uid": uid,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
    }
    token = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


# Dependencies
def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: sqlite3.Connection = Depends(get_db),
) -> dict:
    token = creds.credentials
    payload = decode_token(token)
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    # Fetch user securely via parameterized query to prevent SQL injection (CWE-89)
    cur = db.execute("SELECT id, email, username FROM users WHERE username = ? LIMIT 1", (username,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    return {"id": row["id"], "email": row["email"], "username": row["username"]}


# Exception handler to return {"message": "..."} per schema for errors
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Avoid leaking sensitive details; provide standardized "message" field
    detail = exc.detail
    if isinstance(detail, dict):
        message = detail.get("message", "Error")
    elif isinstance(detail, str):
        message = detail
    else:
        message = "Error"
    return JSONResponse(status_code=exc.status_code, content={"message": message})


# Routes
@app.post("/register", status_code=status.HTTP_201_CREATED, tags=["Authentication"])
def register(payload: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    # Hash the password securely for storage (CWE-522)
    password_hash = pbkdf2_sha256.hash(payload.password)
    created_at = datetime.now(timezone.utc).isoformat()
    try:
        # Use parameterized query to avoid SQL injection (CWE-89)
        db.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (payload.email, payload.username, password_hash, created_at),
        )
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Email or username already in use
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")
    except Exception:
        # Handle unexpected DB errors gracefully (CWE-703)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")


@app.post("/login", status_code=status.HTTP_200_OK, tags=["Authentication"])
def login(payload: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    try:
        cur = db.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ? LIMIT 1",
            (payload.email,),
        )
        row = cur.fetchone()
    except Exception:
        # Unexpected DB error
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    if not row:
        # Do not reveal whether the email exists (CWE-522 - avoid info leakage)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    stored_hash = row["password_hash"]
    try:
        if not pbkdf2_sha256.verify(payload.password, stored_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    except Exception:
        # Verification failed or unexpected error
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    token = create_access_token(username=row["username"], uid=row["id"], email=row["email"])
    return {"token": token, "message": "Login successful"}


@app.post("/set_secret", status_code=status.HTTP_200_OK)
def set_secret(
    payload: SetSecretRequest,
    current_user: dict = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    # Enforce that the actor can only set their own secret (CWE-284, CWE-863)
    if payload.username != current_user["username"]:
        # Invalid token for the given username
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    updated_at = datetime.now(timezone.utc).isoformat()
    user_id = current_user["id"]

    try:
        # Upsert secret securely using parameterized queries (CWE-89)
        # Using SQLite UPSERT syntax (supported by SQLite >= 3.24)
        db.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret=excluded.secret,
                updated_at=excluded.updated_at
            """,
            (user_id, payload.secret, updated_at),
        )
        return {"message": "Secret has been set successfully"}
    except Exception:
        # Handle unexpected DB errors gracefully (CWE-703)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


@app.get("/get_secret", status_code=status.HTTP_200_OK)
def get_secret(
    username: constr(regex=r"^[A-Za-z0-9_]{3,32}$"),
    current_user: dict = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    # Enforce that the actor can only get their own secret (CWE-284, CWE-863)
    if username != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    try:
        cur = db.execute(
            """
            SELECT s.secret FROM secrets s
            JOIN users u ON s.user_id = u.id
            WHERE u.username = ?
            LIMIT 1
            """,
            (username,),
        )
        row = cur.fetchone()
        secret_value = row["secret"] if row else ""
        return {"secret": secret_value}
    except Exception:
        # Unexpected DB error
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


# Customize OpenAPI to align with provided schema
def custom_openapi():
    from fastapi.openapi.utils import get_openapi

    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=APP_TITLE,
        version=APP_VERSION,
        description=APP_DESCRIPTION,
        routes=app.routes,
    )
    # Security schemes and global security
    openapi_schema.setdefault("components", {}).setdefault("securitySchemes", {})
    openapi_schema["components"]["securitySchemes"]["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    openapi_schema["security"] = [{"bearerAuth": []}]
    # Explicitly mark /register and /login as not requiring security
    if "/register" in openapi_schema.get("paths", {}) and "post" in openapi_schema["paths"]["/register"]:
        openapi_schema["paths"]["/register"]["post"]["security"] = []
        openapi_schema["paths"]["/register"]["post"]["summary"] = "User registration"
        openapi_schema["paths"]["/register"]["post"]["description"] = (
            "Register a new user with email, username and password."
        )
    if "/login" in openapi_schema.get("paths", {}) and "post" in openapi_schema["paths"]["/login"]:
        openapi_schema["paths"]["/login"]["post"]["security"] = []
        openapi_schema["paths"]["/login"]["post"]["summary"] = "User login"
        openapi_schema["paths"]["/login"]["post"]["description"] = "Authenticate a user with email and password."
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# Initialize DB on startup
init_db()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5000)