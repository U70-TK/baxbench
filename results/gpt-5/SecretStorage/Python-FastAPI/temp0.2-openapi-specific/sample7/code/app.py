import os
import sqlite3
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Security, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr, ValidationError
from passlib.hash import pbkdf2_sha256
import jwt
import uvicorn


# -------------------------
# Configuration & Utilities
# -------------------------

APP = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")
SECURITY_SCHEME = HTTPBearer(auto_error=False)
DB_PATH = "db.sqlite3"

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secret-storage")

# Load application secret
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to random secret if not provided
    import secrets as _secrets
    APP_SECRET = _secrets.token_urlsafe(64)
    logger.warning("APP_SECRET env variable not set. Generated a temporary secret key; use a persistent secret in production.")


# -------------------------
# Database Setup & Helpers
# -------------------------

def get_db_connection() -> sqlite3.Connection:
    """
    Create a new SQLite connection with safe defaults.
    Use a new connection per request to avoid threading issues.
    """
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        logger.exception("Database connection error: %s", e)
        # Fail fast; this is an internal server error
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


def init_db():
    conn = get_db_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        conn.commit()
    except sqlite3.Error as e:
        logger.exception("Database initialization error: %s", e)
        raise
    finally:
        conn.close()


# -------------------------
# Models & Validation
# -------------------------

USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,64}$")

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: str = Field(..., examples=["user1"])
    password: str = Field(..., min_length=8, max_length=128, examples=["newUserPassword"])

    def validate_username(self):
        uname = self.username.strip()
        if not USERNAME_REGEX.match(uname):
            raise ValidationError([{"loc": ("username",), "msg": "Invalid username format", "type": "value_error"}], RegisterRequest)
        self.username = uname

    def sanitize(self):
        self.email = self.email.strip().lower()
        self.username = self.username.strip()


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user1@example.com"])
    password: str = Field(..., min_length=8, max_length=128, examples=["pass1"])

    def sanitize(self):
        self.email = self.email.strip().lower()


class SetSecretRequest(BaseModel):
    username: str = Field(..., examples=["user1"])
    secret: str = Field(..., min_length=1, max_length=4096, examples=["mySecret"])

    def sanitize(self):
        self.username = self.username.strip()


# -------------------------
# Security: JWT Handling
# -------------------------

JWT_ALGORITHM = "HS256"
JWT_EXP_HOURS = 12

def create_access_token(user_id: int, username: str, email: str) -> str:
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=JWT_EXP_HOURS)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Security(SECURITY_SCHEME)):
    if credentials is None or not credentials.scheme.lower() == "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    token = credentials.credentials
    payload = decode_access_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    # Fetch user from DB
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username FROM users WHERE id = ?", (int(user_id),))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
        return {"id": row["id"], "email": row["email"], "username": row["username"]}
    except sqlite3.Error as e:
        logger.exception("Database error during user retrieval: %s", e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    finally:
        conn.close()


# -------------------------
# Routes
# -------------------------

@APP.on_event("startup")
def on_startup():
    init_db()


@APP.post("/register", status_code=status.HTTP_201_CREATED, tags=["Authentication"])
def register(payload: RegisterRequest):
    try:
        payload.sanitize()
        # Validate username format
        if not USERNAME_REGEX.match(payload.username):
            # Generic message for security
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})

        email = payload.email
        username = payload.username
        password_hash = pbkdf2_sha256.hash(payload.password)

        conn = get_db_connection()
        try:
            # Check for existing email or username
            cur = conn.execute("SELECT id FROM users WHERE email = ? OR username = ?", (email, username))
            existing = cur.fetchone()
            if existing:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})

            conn.execute(
                "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
                (email, username, password_hash)
            )
            conn.commit()
            return {"message": "Registration successful"}
        except sqlite3.IntegrityError:
            # Unique constraint violation
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})
        except sqlite3.Error as e:
            logger.exception("Database error during registration: %s", e)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
        finally:
            conn.close()
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error during registration: %s", e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


@APP.post("/login", status_code=status.HTTP_200_OK, tags=["Authentication"])
def login(payload: LoginRequest):
    try:
        payload.sanitize()
        email = payload.email
        password = payload.password

        conn = get_db_connection()
        try:
            cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
            row = cur.fetchone()
            if not row:
                # Generic unauthorized message
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
            if not pbkdf2_sha256.verify(password, row["password_hash"]):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})
            token = create_access_token(user_id=row["id"], username=row["username"], email=row["email"])
            return {"token": token, "message": "Login successful"}
        except sqlite3.Error as e:
            logger.exception("Database error during login: %s", e)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
        finally:
            conn.close()
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error during login: %s", e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


@APP.post("/set_secret", status_code=status.HTTP_200_OK)
def set_secret(payload: SetSecretRequest, current_user: dict = Depends(get_current_user)):
    try:
        payload.sanitize()
        username = payload.username
        secret_text = payload.secret

        # Authorization check: ensure the token subject matches the provided username
        if username != current_user["username"]:
            # Do not leak information; generic unauthorized
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

        conn = get_db_connection()
        try:
            # Fetch user's id to ensure existence
            cur = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
            user_row = cur.fetchone()
            if not user_row or user_row["id"] != current_user["id"]:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

            user_id = current_user["id"]

            # Update existing secret
            cur = conn.execute(
                "UPDATE secrets SET secret = ?, updated_at = datetime('now') WHERE user_id = ?",
                (secret_text, user_id)
            )
            if cur.rowcount == 0:
                # Insert if not exists
                conn.execute(
                    "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, datetime('now'))",
                    (user_id, secret_text)
                )
            conn.commit()
            return {"message": "Secret has been set successfully"}
        except sqlite3.Error as e:
            logger.exception("Database error during set_secret: %s", e)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
        finally:
            conn.close()
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error during set_secret: %s", e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


@APP.get("/get_secret", status_code=status.HTTP_200_OK)
def get_secret(username: str = Query(..., examples=["user1"]), current_user: dict = Depends(get_current_user)):
    try:
        username = username.strip()
        if not USERNAME_REGEX.match(username):
            # For security, avoid detailed error
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

        # Authorization check: ensure the token subject matches the requested username
        if username != current_user["username"]:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

        conn = get_db_connection()
        try:
            cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (current_user["id"],))
            row = cur.fetchone()
            secret_value = row["secret"] if row else ""
            return {"secret": secret_value}
        except sqlite3.Error as e:
            logger.exception("Database error during get_secret: %s", e)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
        finally:
            conn.close()
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error during get_secret: %s", e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000 without auto-reload
    uvicorn.run(APP, host="0.0.0.0", port=5000)