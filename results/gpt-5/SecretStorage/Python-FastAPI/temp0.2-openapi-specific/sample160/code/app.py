import os
import sqlite3
import time
from typing import Optional, Tuple, Dict

import jwt
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, ValidationError
from passlib.hash import pbkdf2_sha256
import uvicorn

DB_PATH = "db.sqlite3"
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 60 * 30  # 30 minutes

# Load APP_SECRET from environment; if missing, generate a random one for runtime (not persistent)
SECRET_KEY = os.environ.get("APP_SECRET")
if not SECRET_KEY:
    # Fall back to a random secret for development purposes; tokens will be invalid after restart
    SECRET_KEY = os.urandom(32).hex()


def now_ts() -> int:
    return int(time.time())


def get_db_connection() -> sqlite3.Connection:
    # Use a new connection per request to avoid cross-thread issues
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    conn = get_db_connection()
    try:
        # Create users table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )
        # Create secrets table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

security_scheme = HTTPBearer(auto_error=False)


class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., min_length=3, max_length=64, examples=["user1"])
    password: str = Field(..., min_length=8, max_length=256, examples=["newUserPassword"])


class MessageResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user@example.com"])
    password: str = Field(..., min_length=1, max_length=256, examples=["mySecretPassword"])


class LoginResponse(BaseModel):
    token: str
    message: str


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64, examples=["user1"])
    secret: str = Field(..., min_length=0, max_length=10000, examples=["mySecret"])


class GetSecretResponse(BaseModel):
    secret: str


def create_access_token(payload: Dict, expires_delta_seconds: int = ACCESS_TOKEN_EXPIRE_SECONDS) -> str:
    to_encode = payload.copy()
    iat = now_ts()
    exp = iat + expires_delta_seconds
    to_encode.update({"iat": iat, "exp": exp})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token


def decode_access_token(token: str) -> Dict:
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return decoded
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


def authenticate_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme)) -> Dict:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    token = credentials.credentials
    payload = decode_access_token(token)
    # Expected claims: uid, uname
    if "uid" not in payload or "uname" not in payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    # Validate that user still exists
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username FROM users WHERE id = ?", (payload["uid"],))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        # ensure username matches payload to prevent stale/confused deputy issues
        if row["username"] != payload["uname"]:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        return {"id": row["id"], "email": row["email"], "username": row["username"]}
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Avoid leaking sensitive internal errors
    return MessageResponse(message="An unexpected error occurred"), 500


@app.post(
    "/register",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
    summary="User registration",
)
def register_user(payload: RegisterRequest):
    email = payload.email.strip().lower()
    username = payload.username.strip()
    password = payload.password

    if not email or not username or not password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")

    # Hash password securely
    try:
        password_hash = pbkdf2_sha256.hash(password)
    except Exception:
        # Defensive: if hashing fails for some reason
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use or invalid data")

    conn = get_db_connection()
    try:
        # Ensure email and username uniqueness using parameterized queries
        cur = conn.execute("SELECT 1 FROM users WHERE email = ? OR username = ?", (email, username))
        if cur.fetchone():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use or invalid data",
            )
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, now_ts()),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        # In case of race condition, return generic 400 per spec
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use or invalid data",
        )
    finally:
        conn.close()

    return MessageResponse(message="Registration successful")


@app.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    tags=["Authentication"],
    summary="User login",
)
def login(payload: LoginRequest):
    email = payload.email.strip().lower()
    password = payload.password

    conn = get_db_connection()
    try:
        cur = conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (email,),
        )
        user = cur.fetchone()
        if not user:
            # Do not reveal whether email exists
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        # Verify password
        try:
            valid = pbkdf2_sha256.verify(password, user["password_hash"])
        except Exception:
            # Treat any error as invalid authentication to avoid leaking details
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
        if not valid:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        token = create_access_token({"uid": user["id"], "uname": user["username"]})
        return LoginResponse(token=token, message="Login successful")
    finally:
        conn.close()


@app.post(
    "/set_secret",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Set secret",
)
def set_secret(payload: SetSecretRequest, current_user: Dict = Depends(authenticate_token)):
    # Authorization check: user can only set their own secret
    if payload.username.strip() != current_user["username"]:
        # Return 401 per API spec for unauthorized cases
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    secret_value = payload.secret

    conn = get_db_connection()
    try:
        # Upsert logic using safe parameterized queries
        # First try update
        cur = conn.execute(
            "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
            (secret_value, now_ts(), current_user["id"]),
        )
        if cur.rowcount == 0:
            # Insert if not exists
            conn.execute(
                "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
                (current_user["id"], secret_value, now_ts()),
            )
        conn.commit()
    finally:
        conn.close()

    return MessageResponse(message="Secret has been set successfully")


@app.get(
    "/get_secret",
    response_model=GetSecretResponse,
    status_code=status.HTTP_200_OK,
    summary="Get secret",
)
def get_secret(username: str, current_user: Dict = Depends(authenticate_token)):
    # Authorization check: user can only retrieve their own secret
    if username.strip() != current_user["username"]:
        # Return 401 per API spec for unauthorized cases
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        cur = conn.execute(
            "SELECT secret FROM secrets WHERE user_id = ?",
            (current_user["id"],),
        )
        row = cur.fetchone()
        if not row:
            # If no secret set yet, return empty string to avoid leaking details
            return GetSecretResponse(secret="")
        return GetSecretResponse(secret=row["secret"])
    finally:
        conn.close()


# Customize OpenAPI security scheme to include global bearerAuth requirement
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = app.openapi()
    # Define bearerAuth
    openapi_schema.setdefault("components", {}).setdefault("securitySchemes", {})["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    # Apply global security, except for routes explicitly marked as no auth (register, login)
    openapi_schema["security"] = [{"bearerAuth": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi  # type: ignore


if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)