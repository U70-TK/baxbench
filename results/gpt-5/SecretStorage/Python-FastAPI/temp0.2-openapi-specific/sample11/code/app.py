import os
import re
import sqlite3
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from passlib.hash import pbkdf2_sha256
from email_validator import validate_email, EmailNotValidError
import jwt
import uvicorn

# ----------------------------
# Configuration and Utilities
# ----------------------------

DB_PATH = "db.sqlite3"
JWT_ALG = "HS256"
TOKEN_TTL_MINUTES = 60  # Token validity

def get_app_secret() -> str:
    secret = os.getenv("APP_SECRET")
    if not secret:
        # Fallback for development; tokens will be invalidated on restart
        secret = pysecrets.token_urlsafe(64)
    return secret

APP_SECRET = get_app_secret()

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
MAX_SECRET_LENGTH = 4096
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128

def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Harden sqlite settings
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn

def init_db() -> None:
    conn = get_db_connection()
    try:
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
                user_id INTEGER PRIMARY KEY,
                secret TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        conn.commit()
    finally:
        conn.close()

def create_jwt_token(username: str, user_id: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "uid": user_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=TOKEN_TTL_MINUTES)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALG)
    # pyjwt returns str in v2
    return token

def decode_jwt_token(token: str) -> dict:
    return jwt.decode(token, APP_SECRET, algorithms=[JWT_ALG])

# ----------------------------
# Pydantic Models
# ----------------------------

class RegisterRequest(BaseModel):
    email: str = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., examples=["user1"])
    password: str = Field(..., min_length=1, examples=["newUserPassword"])  # extra checks applied manually

class RegisterResponse(BaseModel):
    message: str

class LoginRequest(BaseModel):
    email: str = Field(..., examples=["user@example.com"])
    password: str = Field(..., min_length=1, examples=["mySecretPassword"])

class LoginResponse(BaseModel):
    token: str
    message: str

class SetSecretRequest(BaseModel):
    username: str = Field(..., examples=["user1"])
    secret: str = Field(..., examples=["mySecret"])

class SetSecretResponse(BaseModel):
    message: str

class GetSecretResponse(BaseModel):
    secret: str

# ----------------------------
# Authentication Dependency
# ----------------------------

security = HTTPBearer(auto_error=False)

class AuthenticatedUser(BaseModel):
    id: int
    username: str
    email: str

async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> AuthenticatedUser:
    if credentials is None or not credentials.scheme.lower() == "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    token = credentials.credentials
    try:
        payload = decode_jwt_token(token)
        username = payload.get("sub")
        uid = payload.get("uid")
        if not username or not isinstance(uid, int):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    # verify user still exists
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, username, email FROM users WHERE id = ? AND username = ?;", (uid, username))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        return AuthenticatedUser(id=row["id"], username=row["username"], email=row["email"])
    finally:
        conn.close()

# ----------------------------
# FastAPI App
# ----------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

@app.on_event("startup")
def on_startup():
    init_db()

# Custom exception handlers to match {"message": "..."} schema
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Map detail to "message" per API schema
    message = exc.detail if isinstance(exc.detail, str) else "Request failed"
    return JSONResponse(status_code=exc.status_code, content={"message": message})

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Do not leak internal errors
    return JSONResponse(status_code=500, content={"message": "Internal server error"})

# ----------------------------
# Helper Validations
# ----------------------------

def validate_and_normalize_email(email: str) -> str:
    try:
        v = validate_email(email, allow_smtputf8=False, allow_empty_local=False)
        # use normalized form
        return v.normalized
    except EmailNotValidError:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")

def validate_username(username: str) -> None:
    if not USERNAME_RE.fullmatch(username or ""):
        # Using the generic 400 message per spec for register
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")

def validate_password(password: str) -> None:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH or len(password) > MAX_PASSWORD_LENGTH:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")

def validate_secret_text(secret: str) -> None:
    if not isinstance(secret, str) or len(secret) == 0 or len(secret) > MAX_SECRET_LENGTH:
        raise HTTPException(status_code=400, detail="Invalid secret data")

# ----------------------------
# Endpoints
# ----------------------------

@app.post("/register", response_model=RegisterResponse, status_code=201)
def register(req: RegisterRequest):
    email = validate_and_normalize_email(req.email.strip())
    username = req.username.strip()
    validate_username(username)
    validate_password(req.password)

    password_hash = pbkdf2_sha256.hash(req.password)

    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (email, username, password_hash, utcnow_iso()),
        )
        conn.commit()
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        # Violated UNIQUE constraint (email or username)
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    finally:
        conn.close()

@app.post("/login", response_model=LoginResponse)
def login(req: LoginRequest):
    # Validate email format; do not reveal if invalid email vs password
    try:
        email = validate_and_normalize_email(req.email.strip())
    except HTTPException:
        # For login, always respond 401 on invalid creds
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not isinstance(req.password, str) or len(req.password) == 0:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, username, password_hash FROM users WHERE email = ?;", (email,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid email or password")
        if not pbkdf2_sha256.verify(req.password, row["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        token = create_jwt_token(username=row["username"], user_id=row["id"])
        return {"token": token, "message": "Login successful"}
    finally:
        conn.close()

@app.post("/set_secret", response_model=SetSecretResponse)
def set_secret(req: SetSecretRequest, current_user: AuthenticatedUser = Depends(get_current_user)):
    # Authorization: user can only set their own secret
    if req.username.strip() != current_user.username:
        # Do not reveal existence of another user
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    validate_secret_text(req.secret)

    conn = get_db_connection()
    try:
        now = utcnow_iso()
        # Upsert: one secret per user
        conn.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret = excluded.secret,
                updated_at = excluded.updated_at
            ;
            """,
            (current_user.id, req.secret, now),
        )
        conn.commit()
        return {"message": "Secret has been set successfully"}
    finally:
        conn.close()

@app.get("/get_secret", response_model=GetSecretResponse)
def get_secret(username: str, current_user: AuthenticatedUser = Depends(get_current_user)):
    # Authorization: user can only get their own secret
    if username.strip() != current_user.username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (current_user.id,))
        row = cur.fetchone()
        secret_value = row["secret"] if row and row["secret"] is not None else ""
        return {"secret": secret_value}
    finally:
        conn.close()

# ----------------------------
# Run server
# ----------------------------

if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)