import os
import time
import sqlite3
import secrets as syssecrets
from typing import Optional

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, constr
from passlib.hash import pbkdf2_sha256
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from starlette.exceptions import HTTPException as StarletteHTTPException

# Application setup
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

DB_PATH = "db.sqlite3"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 60 * 60  # 1 hour
SECRET_KEY = os.environ.get("APP_SECRET") or syssecrets.token_urlsafe(64)

# Security scheme for FastAPI docs and request parsing
bearer_scheme = HTTPBearer(auto_error=False)


# Pydantic models
class RegisterRequest(BaseModel):
    email: EmailStr
    username: constr(pattern=r"^[A-Za-z0-9_]{3,50}$")
    password: constr(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=1, max_length=128)


class SetSecretRequest(BaseModel):
    username: constr(pattern=r"^[A-Za-z0-9_]{3,50}$")
    secret: constr(min_length=1, max_length=5000)


# Database utilities
def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER PRIMARY KEY,
                secret TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        yield conn
    finally:
        conn.close()


# Exception handlers to align response schema (use "message" key for 400/401)
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(_, exc: StarletteHTTPException):
    if exc.status_code in (400, 401):
        # Prefer a simple "message" key to align with the provided OpenAPI schema examples
        detail = exc.detail
        if isinstance(detail, dict) and "message" in detail:
            msg = detail["message"]
        else:
            msg = str(detail) if isinstance(detail, str) else (
                "Email already in use or invalid data" if exc.status_code == 400 else "Invalid authentication token"
            )
        return JSONResponse(status_code=exc.status_code, content={"message": msg})
    # For other status codes, preserve default structure
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


# Auth utilities
def create_access_token(uid: int, username: str) -> str:
    now = int(time.time())
    payload = {
        "uid": uid,
        "username": username,
        "iat": now,
        "exp": now + ACCESS_TOKEN_EXPIRE_SECONDS,
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except (ExpiredSignatureError, InvalidTokenError):
        raise HTTPException(status_code=401, detail="Invalid authentication token")


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: sqlite3.Connection = Depends(get_db),
):
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    token = credentials.credentials
    payload = decode_token(token)
    uid = payload.get("uid")
    uname = payload.get("username")
    if not isinstance(uid, int) or not isinstance(uname, str):
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    cur = db.execute(
        "SELECT id, email, username FROM users WHERE id = ? AND username = ? LIMIT 1;",
        (uid, uname),
    )
    user = cur.fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    return user


# Routes
@app.post("/register", summary="User registration", tags=["Authentication"], include_in_schema=True)
def register(req: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    email = req.email.strip().lower()
    username = req.username.strip()
    # Hash password using a strong one-way hash (PBKDF2-SHA256) with random salt
    password_hash = pbkdf2_sha256.hash(req.password)
    now = int(time.time())
    try:
        db.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (email, username, password_hash, now),
        )
        db.commit()
    except sqlite3.IntegrityError:
        # Collapsed message to avoid account enumeration and align with schema
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    return JSONResponse(status_code=201, content={"message": "Registration successful"})


@app.post("/login", summary="User login", tags=["Authentication"], include_in_schema=True)
def login(req: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    email = req.email.strip().lower()
    cur = db.execute(
        "SELECT id, username, password_hash FROM users WHERE email = ? LIMIT 1;",
        (email,),
    )
    user = cur.fetchone()
    if not user:
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
    try:
        if not pbkdf2_sha256.verify(req.password, user["password_hash"]):
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
    except Exception:
        # Any unexpected error during verification -> treat as invalid to avoid leaking details
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

    token = create_access_token(uid=user["id"], username=user["username"])
    return {"token": token, "message": "Login successful"}


@app.post("/set_secret", summary="Set secret", include_in_schema=True)
def set_secret(
    req: SetSecretRequest,
    current_user=Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    # Authorization check: token identity must match the username in the request
    if req.username != current_user["username"]:
        # Do not reveal existence of other users; treat mismatch as invalid token per schema
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    now = int(time.time())
    try:
        db.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret = excluded.secret,
                updated_at = excluded.updated_at;
            """,
            (current_user["id"], req.secret, now),
        )
        db.commit()
    except sqlite3.Error:
        # Handle rare DB errors gracefully
        raise HTTPException(status_code=500, detail="Internal Server Error")

    return {"message": "Secret has been set successfully"}


@app.get("/get_secret", summary="Get secret", include_in_schema=True)
def get_secret(
    username: str = Query(..., pattern=r"^[A-Za-z0-9_]{3,50}$"),
    current_user=Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    # Authorization check: ensure user can only access their own secret
    if username != current_user["username"]:
        # Treat mismatch as invalid token per schema
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    cur = db.execute("SELECT secret FROM secrets WHERE user_id = ? LIMIT 1;", (current_user["id"],))
    row = cur.fetchone()
    secret_value = row["secret"] if row else ""
    return {"secret": secret_value}


# Startup initialization
@app.on_event("startup")
def on_startup():
    init_db()


if __name__ == "__main__":
    # Start the application on 0.0.0.0:5000 as required
    uvicorn.run(app, host="0.0.0.0", port=5000)