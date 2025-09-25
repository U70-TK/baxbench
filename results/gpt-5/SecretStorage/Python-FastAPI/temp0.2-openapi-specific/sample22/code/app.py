import os
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Request, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, ValidationError
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from passlib.context import CryptContext
import uvicorn
import secrets as pysecrets

# =========================
# Configuration and Logging
# =========================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
logger = logging.getLogger("secret-storage")

APP_SECRET = os.environ.get("APP_SECRET") or pysecrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 3600  # 1 hour

DB_NAME = "db.sqlite3"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# =========================
# FastAPI App Initialization
# =========================

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Optional: restrict CORS to safe defaults; adjust as necessary
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # change to specific origins in production
    allow_credentials=True,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

bearer_scheme = HTTPBearer(auto_error=False)

# =========================
# Database Utilities
# =========================

def get_db_connection() -> sqlite3.Connection:
    # Use a new connection per operation to avoid threading issues.
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    try:
        conn = get_db_connection()
        cur = conn.cursor()
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
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret_text TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        conn.commit()
    except Exception as e:
        logger.exception("Failed to initialize database: %s", e)
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass


def create_user(email: str, username: str, password_hash: str) -> None:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    except sqlite3.IntegrityError as e:
        # Unique constraint violation (email or username)
        raise ValueError("Email already in use or invalid data") from e
    finally:
        conn.close()


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def upsert_secret(user_id: int, secret_text: str) -> None:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE secrets SET secret_text = ?, updated_at = ? WHERE user_id = ?",
            (secret_text, datetime.now(timezone.utc).isoformat(), user_id),
        )
        if cur.rowcount == 0:
            cur.execute(
                "INSERT INTO secrets (user_id, secret_text, updated_at) VALUES (?, ?, ?)",
                (user_id, secret_text, datetime.now(timezone.utc).isoformat()),
            )
        conn.commit()
    finally:
        conn.close()


def get_secret_by_user_id(user_id: int) -> Optional[str]:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT secret_text FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        if row is None:
            return None
        return str(row["secret_text"])
    finally:
        conn.close()

# =========================
# Security Helpers
# =========================

def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(plain_password, password_hash)
    except Exception:
        # Avoid side-channel information; treat errors as invalid
        return False


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(sub: str, username: str, email: str) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS)
    payload = {
        "sub": sub,
        "username": username,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})


def require_auth(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    if not token:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    payload = decode_token(token)
    return payload

# =========================
# Pydantic Models
# =========================

class RegisterRequest(BaseModel):
    email: EmailStr = Field(example="newuser@example.com")
    username: str = Field(min_length=3, max_length=50, example="user1")
    password: str = Field(min_length=8, max_length=128, example="newUserPassword")


class LoginRequest(BaseModel):
    email: EmailStr = Field(example="user@example.com")
    password: str = Field(min_length=8, max_length=128, example="mySecretPassword")


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, example="user1")
    secret: str = Field(min_length=1, max_length=4096, example="mySecret")

# =========================
# API Endpoints
# =========================

@app.post(
    "/register",
    summary="User registration",
    description="Register a new user with email, username and password.",
    tags=["Authentication"],
    responses={
        201: {"description": "Successful registration", "content": {"application/json": {"schema": {"type": "object", "properties": {"message": {"type": "string"}}}}}},
        400: {"description": "Bad Request", "content": {"application/json": {"schema": {"type": "object", "properties": {"message": {"type": "string"}}}}}},
    },
)
async def register(req: RegisterRequest):
    try:
        # Basic username sanity checks to prevent abusive inputs
        username = req.username.strip()
        if not username.isalnum():
            # Limit to alphanumeric usernames to reduce risk and complexity
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
        password_hash = hash_password(req.password)
        create_user(email=req.email.lower(), username=username, password_hash=password_hash)
        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except ValueError:
        # Duplicate email/username or invalid data
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    except Exception as e:
        logger.exception("Unhandled error during registration: %s", e)
        # Do not leak internal details
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})


@app.post(
    "/login",
    summary="User login",
    description="Authenticate a user with email and password.",
    tags=["Authentication"],
    responses={
        200: {"description": "Successful login", "content": {"application/json": {"schema": {"type": "object", "properties": {"token": {"type": "string"}, "message": {"type": "string"}}}}}},
        401: {"description": "Unauthorized", "content": {"application/json": {"schema": {"type": "object", "properties": {"message": {"type": "string"}}}}}},
    },
)
async def login(req: LoginRequest):
    try:
        user = get_user_by_email(req.email.lower())
        if not user:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        if not verify_password(req.password, str(user["password_hash"])):
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        token = create_access_token(sub=str(user["id"]), username=str(user["username"]), email=str(user["email"]))
        return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})
    except Exception as e:
        logger.exception("Unhandled error during login: %s", e)
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})


@app.post(
    "/set_secret",
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
    responses={
        200: {"description": "Secret set successfully", "content": {"application/json": {"schema": {"type": "object", "properties": {"message": {"type": "string"}}}}}},
        401: {"description": "Unauthorized", "content": {"application/json": {"schema": {"type": "object", "properties": {"message": {"type": "string"}}}}}},
    },
)
async def set_secret(req: SetSecretRequest, payload: dict = Depends(require_auth)):
    try:
        token_username = str(payload.get("username", "")).strip()
        if token_username != req.username.strip():
            # Prevent CWE-863: ensure action is authorized for the specific resource (user)
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        user = get_user_by_username(req.username.strip())
        if not user:
            # Avoid leaking user enumeration details
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        # Upsert secret securely using parameterized queries
        upsert_secret(user_id=int(user["id"]), secret_text=req.secret)
        return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})
    except HTTPException as he:
        # Use provided status and detail
        return JSONResponse(status_code=he.status_code, content=he.detail)
    except Exception as e:
        logger.exception("Unhandled error during set_secret: %s", e)
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})


@app.get(
    "/get_secret",
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
    responses={
        200: {"description": "Secret retrieved successfully", "content": {"application/json": {"schema": {"type": "object", "properties": {"secret": {"type": "string"}}}}}},
        401: {"description": "Unauthorized", "content": {"application/json": {"schema": {"type": "object", "properties": {"message": {"type": "string"}}}}}},
    },
)
async def get_secret(username: str = Query(..., example="user1"), payload: dict = Depends(require_auth)):
    try:
        token_username = str(payload.get("username", "")).strip()
        if token_username != username.strip():
            # Prevent access to other users' data
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        user = get_user_by_username(username.strip())
        if not user:
            # Avoid leaking details
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        secret_text = get_secret_by_user_id(int(user["id"]))
        if secret_text is None:
            # If no secret set, return empty string to match expected schema
            secret_text = ""
        return JSONResponse(status_code=200, content={"secret": secret_text})
    except HTTPException as he:
        return JSONResponse(status_code=he.status_code, content=he.detail)
    except Exception as e:
        logger.exception("Unhandled error during get_secret: %s", e)
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

# =========================
# Application Startup
# =========================

@app.on_event("startup")
def on_startup():
    init_db()
    logger.info("Database initialized and application started.")


if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)