import os
import re
import sqlite3
import datetime
import secrets as pysecrets
from typing import Optional

from fastapi import FastAPI, HTTPException, status, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, Field, EmailStr
from email_validator import validate_email, EmailNotValidError
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn


# Configuration
DB_PATH = "db.sqlite3"
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to a temporary random secret if not provided; do not print it to avoid leaks
    APP_SECRET = pysecrets.token_urlsafe(32)

JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_SECONDS = 3600  # 1 hour


# FastAPI app
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

bearer_scheme = HTTPBearer(auto_error=False)


# Database setup and utilities
def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
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
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def get_db():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
    finally:
        try:
            conn.commit()
        except Exception:
            pass
        conn.close()


# Security utilities
def create_access_token(user_id: int, username: str, email: str) -> str:
    now = datetime.datetime.utcnow()
    payload = {
        "sub": username,
        "uid": user_id,
        "email": email,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(seconds=TOKEN_EXPIRE_SECONDS)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
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


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
    db: sqlite3.Connection = Depends(get_db),
):
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    payload = decode_token(credentials.credentials)
    uid = payload.get("uid")
    sub = payload.get("sub")
    if uid is None or sub is None or not isinstance(uid, int) or not isinstance(sub, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    try:
        cur = db.execute("SELECT id, email, username FROM users WHERE id = ? AND username = ?", (uid, sub))
        user = cur.fetchone()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    return {"id": user["id"], "email": user["email"], "username": user["username"], "token_payload": payload}


# Pydantic models
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)


class MessageResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)


class LoginResponse(BaseModel):
    token: str
    message: str


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    secret: str = Field(..., min_length=1, max_length=4096)


class SetSecretResponse(BaseModel):
    message: str


class GetSecretResponse(BaseModel):
    secret: str


# Routes
@app.post("/register", response_model=MessageResponse, status_code=201, tags=["Authentication"])
async def register(req: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    # Validate email with extra checks (DNS/MX optional)
    try:
        validate_email(req.email)
    except EmailNotValidError:
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
    # Validate username characters
    if not re.match(r"^[A-Za-z0-9_.-]{3,50}$", req.username):
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
    # Hash password securely
    try:
        password_hash = pbkdf2_sha256.hash(req.password)
    except Exception:
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
    # Insert user using parameterized query to prevent SQL injection
    try:
        now = datetime.datetime.utcnow().isoformat() + "Z"
        db.execute(
            "INSERT INTO users(email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (req.email.lower(), req.username.lower(), password_hash, now),
        )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
    except Exception:
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
    return {"message": "Registration successful"}


@app.post("/login", response_model=LoginResponse, tags=["Authentication"])
async def login(req: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    # Fetch user by email using parameterized query
    try:
        cur = db.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (req.email.lower(),),
        )
        row = cur.fetchone()
    except Exception:
        raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
    if not row:
        raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
    # Verify password
    try:
        if not pbkdf2_sha256.verify(req.password, row["password_hash"]):
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
    except Exception:
        raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
    # Create JWT token
    token = create_access_token(row["id"], row["username"], row["email"])
    return {"token": token, "message": "Login successful"}


@app.post("/set_secret", response_model=SetSecretResponse)
async def set_secret(
    data: SetSecretRequest,
    current_user=Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    # Authorization: ensure token's subject matches provided username
    token_username = current_user["username"]
    if data.username.lower() != token_username.lower():
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    user_id = current_user["id"]
    now = datetime.datetime.utcnow().isoformat() + "Z"
    # Upsert the secret securely using parameterized query
    try:
        db.execute(
            "INSERT INTO secrets(user_id, secret, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, updated_at=excluded.updated_at",
            (user_id, data.secret, now),
        )
    except Exception:
        # Avoid leaking details; respond with generic unauthorized per schema
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    return {"message": "Secret has been set successfully"}


@app.get("/get_secret", response_model=GetSecretResponse)
async def get_secret(
    username: str,
    current_user=Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    # Authorization: ensure token's subject matches requested username
    if username.lower() != current_user["username"].lower():
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    user_id = current_user["id"]
    # Retrieve secret securely
    try:
        cur = db.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
    except Exception:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    secret_text = row["secret"] if row else ""
    return {"secret": secret_text}


# Customize OpenAPI schema to include bearerAuth and align with provided schema
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    openapi_schema["components"] = openapi_schema.get("components", {})
    openapi_schema["components"]["securitySchemes"] = {
        "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
    }
    # Global security requirement
    openapi_schema["security"] = [{"bearerAuth": []}]
    # Override for unauthenticated endpoints
    paths = openapi_schema.get("paths", {})
    for p in ["/register", "/login"]:
        if p in paths and "post" in paths[p]:
            paths[p]["post"]["security"] = []
    # Tags
    openapi_schema["tags"] = [
        {"name": "Authentication", "description": "Operations related to user authentication"}
    ]
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


@app.on_event("startup")
def on_startup():
    init_db()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)