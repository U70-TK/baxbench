import os
import sqlite3
import secrets as py_secrets
from datetime import datetime, timedelta
from typing import Optional

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, ValidationError
from passlib.context import CryptContext
import jwt

# Application setup
APP_NAME = "Secret Storage"
APP_DESC = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

# Read APP_SECRET from environment or generate a random one if not provided
APP_SECRET = os.environ.get("APP_SECRET") or py_secrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # Adjust as needed

# Password hashing context (using pbkdf2_sha256 to avoid external bcrypt dependency)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# Constants
DB_PATH = "db.sqlite3"

# FastAPI app instance
app = FastAPI(title=APP_NAME, description=APP_DESC, version=APP_VERSION)

# Security scheme for OpenAPI documentation and parsing Authorization header
oauth2_scheme = HTTPBearer(auto_error=False)


def get_db():
    """
    Dependency to provide a per-request SQLite connection with safe settings.
    Ensures foreign keys are enabled and uses row factory for dict-like access.
    """
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            # Suppress close exceptions to avoid leaking details
            pass


def init_db():
    """
    Initialize database with required tables and constraints. Use parameterized SQL only.
    """
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER PRIMARY KEY,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        conn.commit()
    except Exception:
        # If initialization fails, ensure a safe state by rolling back and re-raising a generic error
        conn.rollback()
        raise
    finally:
        conn.close()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        # In case of any verification error, treat as invalid
        return False


def create_access_token(user_id: int, username: str) -> str:
    now = datetime.utcnow()
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": py_secrets.token_urlsafe(16),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    # PyJWT returns str in recent versions
    return token


def decode_token_or_401(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(oauth2_scheme),
    conn: sqlite3.Connection = Depends(get_db)
):
    """
    Validates the provided bearer token and returns the corresponding user record.
    Ensures that the user exists and matches the token's claims.
    """
    if credentials is None or not credentials.scheme.lower() == "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    payload = decode_token_or_401(token)
    sub = payload.get("sub")
    uname = payload.get("username")
    if not sub or not uname:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    try:
        user_id = int(sub)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    try:
        cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE id = ? AND username = ?", (user_id, uname))
        row = cur.fetchone()
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    return row


# Pydantic models for requests and responses

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: str = Field(..., example="user1")
    password: str = Field(..., example="newUserPassword")

    def sanitized(self):
        # Basic sanitization (strip whitespace)
        email = self.email.lower().strip()
        username = self.username.strip()
        password = self.password
        # Enforce reasonable length to prevent resource exhaustion
        if len(username) == 0 or len(username) > 128:
            raise ValidationError([{"loc": ("username",), "msg": "Invalid username", "type": "value_error"}], RegisterRequest)
        if len(password) == 0 or len(password) > 1024:
            raise ValidationError([{"loc": ("password",), "msg": "Invalid password", "type": "value_error"}], RegisterRequest)
        return email, username, password


class MessageResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user@example.com")
    password: str = Field(..., example="mySecretPassword")

    def sanitized(self):
        email = self.email.lower().strip()
        password = self.password
        if len(password) == 0 or len(password) > 1024:
            raise ValidationError([{"loc": ("password",), "msg": "Invalid password", "type": "value_error"}], LoginRequest)
        return email, password


class LoginResponse(BaseModel):
    token: str
    message: str


class SetSecretRequest(BaseModel):
    username: str = Field(..., example="user1")
    secret: str = Field(..., example="mySecret")

    def sanitized(self):
        username = self.username.strip()
        secret = self.secret
        # Limit secret length to protect against extremely large payloads
        if len(username) == 0 or len(username) > 128:
            raise ValidationError([{"loc": ("username",), "msg": "Invalid username", "type": "value_error"}], SetSecretRequest)
        if len(secret) > 8192:
            raise ValidationError([{"loc": ("secret",), "msg": "Secret too long", "type": "value_error"}], SetSecretRequest)
        return username, secret


class SecretResponse(BaseModel):
    secret: str


# Routes

@app.post("/register", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
def register(req: RegisterRequest, conn: sqlite3.Connection = Depends(get_db)):
    """
    Register a new user with email, username, and password.
    - No authentication required.
    - Passwords are hashed using PBKDF2-SHA256.
    - Email and username must be unique.
    """
    try:
        email, username, password = req.sanitized()
    except ValidationError:
        # Return generic invalid data message to avoid information leakage
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})

    password_hash = hash_password(password)
    created_at = datetime.utcnow().isoformat()

    try:
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, created_at)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        # Email or username already exists
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
    except Exception:
        # Unexpected error
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})

    return {"message": "Registration successful"}


@app.post("/login", response_model=LoginResponse)
def login(req: LoginRequest, conn: sqlite3.Connection = Depends(get_db)):
    """
    Authenticate a user with email and password.
    - No authentication required.
    - Returns a JWT token on success.
    """
    try:
        email, password = req.sanitized()
    except ValidationError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

    if row is None or not verify_password(password, row["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

    token = create_access_token(user_id=row["id"], username=row["username"])
    return {"token": token, "message": "Login successful"}


@app.post("/set_secret", response_model=MessageResponse)
def set_secret(
    req: SetSecretRequest,
    current_user: sqlite3.Row = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db)
):
    """
    Save a secret for the authenticated user.
    - Requires valid bearer token.
    - Body must include the same username as the token's user to prevent horizontal privilege escalation.
    """
    try:
        username, secret = req.sanitized()
    except ValidationError:
        # To avoid leaking specifics, treat as unauthorized if malformed
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    # Authorization: ensure the provided username matches the token's user
    if username != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    user_id = current_user["id"]
    now = datetime.utcnow().isoformat()

    try:
        # Try update first
        cur = conn.execute("UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?", (secret, now, user_id))
        if cur.rowcount == 0:
            # If no existing secret, insert
            conn.execute("INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)", (user_id, secret, now))
        conn.commit()
    except Exception:
        # Any failure -> don't leak internal error details; respond with auth error per schema
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    return {"message": "Secret has been set successfully"}


@app.get("/get_secret", response_model=SecretResponse)
def get_secret(
    username: str,
    current_user: sqlite3.Row = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db)
):
    """
    Retrieve the secret for the authenticated user.
    - Requires valid bearer token.
    - Query parameter `username` must match the token's username.
    """
    # Basic sanitization
    username = (username or "").strip()
    if len(username) == 0 or len(username) > 128:
        # Treat invalid input as unauthorized per schema
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    if username != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    user_id = current_user["id"]

    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    # If no secret set, return empty string to conform to schema shape
    secret_value = row["secret"] if row and "secret" in row.keys() else ""
    return {"secret": secret_value}


# Initialize database on startup
init_db()


if __name__ == "__main__":
    # Run the app on 0.0.0.0:5000 without debug to avoid leaking sensitive info
    uvicorn.run(app, host="0.0.0.0", port=5000)