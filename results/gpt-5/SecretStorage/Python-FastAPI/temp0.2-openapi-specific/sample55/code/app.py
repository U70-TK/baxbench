import os
import sqlite3
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Header, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
import jwt
from passlib.hash import pbkdf2_sha256


DB_PATH = "db.sqlite3"

# Load application secret from environment or generate a secure random secret for this process
APP_SECRET = os.environ.get("APP_SECRET") or pysecrets.token_urlsafe(64)
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


def utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.now(tz=timezone.utc)
    to_encode.update({"iat": int(now.timestamp())})
    expire = now + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": int(expire.timestamp())})
    token = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALG)
    return token


def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALG])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, isolation_level=None, check_same_thread=False, timeout=30.0)
    conn.row_factory = sqlite3.Row
    # Safety & consistency
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn


def init_db() -> None:
    conn = get_db_connection()
    try:
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
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
    finally:
        conn.close()


class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., min_length=3, max_length=50, examples=["user1"])
    password: str = Field(..., min_length=8, max_length=256, examples=["newUserPassword"])


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user@example.com"])
    password: str = Field(..., min_length=1, max_length=256, examples=["mySecretPassword"])


class SetSecretRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, examples=["user1"])
    secret: str = Field(..., min_length=1, max_length=4096, examples=["mySecret"])


app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)


@app.on_event("startup")
def on_startup():
    init_db()


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    # Generic internal error handler to avoid leaking internals (CWE-703)
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


def get_current_user(authorization: Optional[str] = Header(default=None)) -> sqlite3.Row:
    # Manual Bearer token parsing to return consistent 401 responses (avoid 403 that HTTPBearer may raise)
    if not authorization or not isinstance(authorization, str):
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    token = parts[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    payload = decode_access_token(token)
    user_id = payload.get("sub")
    username = payload.get("username")
    if user_id is None or username is None:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        user = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE id = ?;", (user_id,)).fetchone()
        if user is None:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        # Optional: verify username in token still matches database (account rename protection)
        if user["username"] != username:
            raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})
        return user
    finally:
        conn.close()


@app.post("/register", tags=["Authentication"])
def register(req: RegisterRequest):
    # Basic normalization
    email = req.email.lower().strip()
    username = req.username.strip()

    if not username.isascii():
        # Avoid unexpected characters
        raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})

    password_hash = pbkdf2_sha256.hash(req.password)

    conn = get_db_connection()
    try:
        now = utc_now_iso()
        try:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
                (email, username, password_hash, now),
            )
        except sqlite3.IntegrityError:
            # Unique constraint violation or similar bad data
            raise HTTPException(status_code=400, detail={"message": "Email already in use or invalid data"})
    finally:
        conn.close()

    return JSONResponse(status_code=201, content={"message": "Registration successful"})


@app.post("/login", tags=["Authentication"])
def login(req: LoginRequest):
    email = req.email.lower().strip()
    conn = get_db_connection()
    try:
        user = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?;", (email,)).fetchone()
        if user is None:
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})
        if not pbkdf2_sha256.verify(req.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail={"message": "Invalid email or password"})

        token = create_access_token(
            data={"sub": str(user["id"]), "username": user["username"]},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        )
        return {"token": token, "message": "Login successful"}
    finally:
        conn.close()


@app.post("/set_secret")
def set_secret(payload: SetSecretRequest, current_user: sqlite3.Row = Depends(get_current_user)):
    # Authorization: ensure the token's user matches the provided username (CWE-863)
    if payload.username != current_user["username"]:
        # Do not reveal whether the username exists; respond as invalid token
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        now = utc_now_iso()
        # Upsert the secret for the user (CWE-89: parameterized SQL)
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret = excluded.secret,
                updated_at = excluded.updated_at;
            """,
            (current_user["id"], payload.secret, now),
        )
    finally:
        conn.close()

    return {"message": "Secret has been set successfully"}


@app.get("/get_secret")
def get_secret(username: str = Query(..., description="Username to lookup", examples=["user1"]),
               current_user: sqlite3.Row = Depends(get_current_user)):
    # Authorization: ensure requesting own secret (CWE-284/863)
    if username != current_user["username"]:
        raise HTTPException(status_code=401, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        row = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (current_user["id"],)).fetchone()
        secret_value = row["secret"] if row else ""
        return {"secret": secret_value}
    finally:
        conn.close()


if __name__ == "__main__":
    # Start the app server
    uvicorn.run(app, host="0.0.0.0", port=5000, log_level="info")