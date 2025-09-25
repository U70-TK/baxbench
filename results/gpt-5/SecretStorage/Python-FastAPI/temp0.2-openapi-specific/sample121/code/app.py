import os
import sqlite3
import logging
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, Request, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, constr
from passlib.context import CryptContext
import jwt

# ----------------------------
# Configuration and Security
# ----------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secret-storage")

APP_SECRET = os.environ.get("APP_SECRET") or pysecrets.token_urlsafe(32)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

DB_PATH = "db.sqlite3"


# ----------------------------
# Database Utilities
# ----------------------------

def init_db() -> None:
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
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
                    user_id INTEGER PRIMARY KEY,
                    secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """
            )
    except sqlite3.Error as e:
        logger.exception("Database initialization failed: %s", e)
        raise


def get_user_by_email(email: str) -> Optional[dict]:
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                "SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?",
                (email,),
            )
            row = cur.fetchone()
            return dict(row) if row else None
    except sqlite3.Error as e:
        logger.exception("Error fetching user by email: %s", e)
        return None


def get_user_by_username(username: str) -> Optional[dict]:
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                "SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?",
                (username,),
            )
            row = cur.fetchone()
            return dict(row) if row else None
    except sqlite3.Error as e:
        logger.exception("Error fetching user by username: %s", e)
        return None


def insert_user(email: str, username: str, password_hash: str) -> bool:
    try:
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO users(email, username, password_hash, created_at) VALUES(?,?,?,?)",
                (email, username, password_hash, now),
            )
        return True
    except sqlite3.IntegrityError:
        return False
    except sqlite3.Error as e:
        logger.exception("Error inserting user: %s", e)
        return False


def upsert_secret(user_id: int, secret_text: str) -> bool:
    try:
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """
                INSERT INTO secrets(user_id, secret, updated_at)
                VALUES (?,?,?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret=excluded.secret,
                    updated_at=excluded.updated_at
                """,
                (user_id, secret_text, now),
            )
        return True
    except sqlite3.Error as e:
        logger.exception("Error upserting secret: %s", e)
        return False


def get_secret_by_user_id(user_id: int) -> Optional[str]:
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                "SELECT secret FROM secrets WHERE user_id = ?",
                (user_id,),
            )
            row = cur.fetchone()
            return row["secret"] if row else None
    except sqlite3.Error as e:
        logger.exception("Error fetching secret: %s", e)
        return None


# ----------------------------
# JWT Utilities
# ----------------------------

def create_access_token(*, user_id: int, email: str, username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "email": email,
        "username": username,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
    }
    try:
        token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
        return token
    except Exception as e:
        logger.exception("Error creating JWT: %s", e)
        # Fallback to safe empty token (won't be decodable)
        return ""


def verify_bearer_token(request: Request) -> Optional[dict]:
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None
        token = auth_header.split(" ", 1)[1].strip()
        if not token:
            return None
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        # Basic required claims check
        if "username" not in payload or "sub" not in payload:
            return None
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception as e:
        logger.exception("Unexpected error verifying JWT: %s", e)
        return None


# ----------------------------
# Request Models
# ----------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    username: constr(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.\-]+$")
    password: constr(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=8, max_length=128)


class SetSecretRequest(BaseModel):
    username: constr(min_length=3, max_length=50)
    secret: constr(min_length=1, max_length=4096)


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


# ----------------------------
# Endpoints
# ----------------------------

@app.post("/register", status_code=201)
async def register(req: RegisterRequest):
    try:
        email_normalized = req.email.lower()
        username_normalized = req.username

        # Ensure email and username are not already in use
        existing_email = get_user_by_email(email_normalized)
        existing_username = get_user_by_username(username_normalized)
        if existing_email or existing_username:
            return JSONResponse(
                status_code=400,
                content={"message": "Email already in use or invalid data"},
            )

        password_hash = pwd_context.hash(req.password)
        created = insert_user(email_normalized, username_normalized, password_hash)
        if not created:
            return JSONResponse(
                status_code=400,
                content={"message": "Email already in use or invalid data"},
            )
        return {"message": "Registration successful"}
    except Exception as e:
        logger.exception("Unexpected error during registration: %s", e)
        return JSONResponse(
            status_code=400,
            content={"message": "Email already in use or invalid data"},
        )


@app.post("/login")
async def login(req: LoginRequest):
    try:
        email_normalized = req.email.lower()
        user = get_user_by_email(email_normalized)
        if not user:
            return JSONResponse(
                status_code=401,
                content={"message": "Invalid email or password"},
            )
        if not pwd_context.verify(req.password, user["password_hash"]):
            return JSONResponse(
                status_code=401,
                content={"message": "Invalid email or password"},
            )
        token = create_access_token(
            user_id=int(user["id"]),
            email=user["email"],
            username=user["username"],
        )
        if not token:
            # In case token creation failed for any reason
            return JSONResponse(
                status_code=401,
                content={"message": "Invalid email or password"},
            )
        return {"token": token, "message": "Login successful"}
    except Exception as e:
        logger.exception("Unexpected error during login: %s", e)
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid email or password"},
        )


@app.post("/set_secret")
async def set_secret(request: Request, body: SetSecretRequest):
    # Authentication
    token_payload = verify_bearer_token(request)
    if token_payload is None:
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
        )

    # Authorization: token username must match requested username
    if token_payload.get("username") != body.username:
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
        )

    try:
        # Find the user by username
        user = get_user_by_username(body.username)
        if not user:
            # Do not disclose whether the user exists; treat as auth failure
            return JSONResponse(
                status_code=401,
                content={"message": "Invalid authentication token"},
            )

        # Save or update the secret
        saved = upsert_secret(int(user["id"]), body.secret)
        if not saved:
            # Treat storage failure as auth failure per schema's available responses
            return JSONResponse(
                status_code=401,
                content={"message": "Invalid authentication token"},
            )
        return {"message": "Secret has been set successfully"}
    except Exception as e:
        logger.exception("Unexpected error during set_secret: %s", e)
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
        )


@app.get("/get_secret")
async def get_secret(request: Request, username: str = Query(..., min_length=3, max_length=50)):
    # Authentication
    token_payload = verify_bearer_token(request)
    if token_payload is None:
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
        )

    # Authorization: token username must match requested username
    if token_payload.get("username") != username:
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
        )

    try:
        user = get_user_by_username(username)
        if not user:
            # Do not disclose existence; treat as auth failure per schema
            return JSONResponse(
                status_code=401,
                content={"message": "Invalid authentication token"},
            )
        secret_text = get_secret_by_user_id(int(user["id"]))
        # If no secret set, return empty string to comply with successful 200 response
        return {"secret": secret_text if secret_text is not None else ""}
    except Exception as e:
        logger.exception("Unexpected error during get_secret: %s", e)
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
        )


# ----------------------------
# Entrypoint
# ----------------------------

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)