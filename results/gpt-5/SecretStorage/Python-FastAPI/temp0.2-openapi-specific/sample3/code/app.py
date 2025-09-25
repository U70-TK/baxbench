import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import uvicorn
from fastapi import FastAPI, Header, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, constr
from passlib.hash import pbkdf2_sha256
import jwt

# Application configuration
APP_NAME = "Secret Storage"
APP_DESCRIPTION = "A secure cloud storage app for string secrets."
APP_VERSION = "1.0.0"

# JWT settings
APP_SECRET = os.getenv("APP_SECRET") or os.urandom(32).hex()
JWT_ALGORITHM = "HS256"
JWT_ISSUER = "secret-storage"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DB_PATH = "db.sqlite3"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_db_connection() -> sqlite3.Connection:
    # Create a new connection per request to avoid thread issues.
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    # Strengthen referential integrity
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    try:
        conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.execute("PRAGMA foreign_keys = ON")
        with conn:
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
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE
                )
                """
            )
    except sqlite3.Error:
        # If initialization fails, exit early; the app will still start,
        # but DB operations will return errors which we handle gracefully.
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def extract_bearer_token(auth_header: Optional[str]) -> Optional[str]:
    if not auth_header:
        return None
    parts = auth_header.strip().split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def create_access_token(user_id: int, username: str) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "iss": JWT_ISSUER,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "sub": username,
        "uid": user_id,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(
            token,
            APP_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["exp", "iat", "iss", "sub"]},
            issuer=JWT_ISSUER,
        )
        return payload
    except jwt.PyJWTError:
        return None


def authenticate(auth_header: Optional[str]) -> Tuple[Optional[sqlite3.Row], Optional[JSONResponse]]:
    token = extract_bearer_token(auth_header)
    if not token:
        return None, JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    payload = decode_token(token)
    if not payload:
        return None, JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    uid = payload.get("uid")
    sub = payload.get("sub")
    if not isinstance(uid, int) or not isinstance(sub, str):
        return None, JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.execute(
            "SELECT id, email, username FROM users WHERE id = ? AND username = ? LIMIT 1",
            (uid, sub),
        )
        user = cur.fetchone()
        if not user:
            return None, JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
        return user, None
    except sqlite3.Error:
        return None, JSONResponse(status_code=500, content={"message": "An unexpected error occurred"})
    finally:
        if conn:
            conn.close()


# Pydantic models for request validation
class RegisterRequest(BaseModel):
    email: EmailStr
    username: constr(strip_whitespace=True, min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_]+$")
    password: constr(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=8, max_length=128)


class SetSecretRequest(BaseModel):
    username: constr(strip_whitespace=True, min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_]+$")
    secret: constr(strip_whitespace=True, min_length=1, max_length=10000)


app = FastAPI(title=APP_NAME, description=APP_DESCRIPTION, version=APP_VERSION)


@app.on_event("startup")
def on_startup():
    init_db()


@app.post("/register", status_code=201)
def register(req: RegisterRequest):
    email = req.email.lower().strip()
    username = req.username.strip()
    password = req.password

    conn = None
    try:
        conn = get_db_connection()
        # Check for duplicates
        cur = conn.execute(
            "SELECT id FROM users WHERE email = ? OR username = ? LIMIT 1",
            (email, username),
        )
        existing = cur.fetchone()
        if existing:
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        password_hash = pbkdf2_sha256.hash(password)
        created_at = utc_now_iso()
        with conn:
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, username, password_hash, created_at),
            )
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    except sqlite3.Error:
        return JSONResponse(status_code=500, content={"message": "An unexpected error occurred"})
    except Exception:
        # Handle any unexpected condition to avoid information disclosure
        return JSONResponse(status_code=500, content={"message": "An unexpected error occurred"})
    finally:
        if conn:
            conn.close()


@app.post("/login")
def login(req: LoginRequest):
    email = req.email.lower().strip()
    password = req.password

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ? LIMIT 1",
            (email,),
        )
        user = cur.fetchone()
        if not user:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        if not pbkdf2_sha256.verify(password, user["password_hash"]):
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

        token = create_access_token(user_id=user["id"], username=user["username"])
        return {"token": token, "message": "Login successful"}
    except sqlite3.Error:
        return JSONResponse(status_code=500, content={"message": "An unexpected error occurred"})
    except Exception:
        return JSONResponse(status_code=500, content={"message": "An unexpected error occurred"})
    finally:
        if conn:
            conn.close()


@app.post("/set_secret")
def set_secret(req: SetSecretRequest, authorization: Optional[str] = Header(default=None)):
    # Authenticate user via Bearer token
    user, error = authenticate(authorization)
    if error:
        return error

    # Authorization check: user can only set their own secret
    if req.username != user["username"]:
        # Do not reveal whether username exists; treat as invalid token scenario
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    conn = None
    try:
        conn = get_db_connection()
        now_iso = utc_now_iso()
        # Upsert secret: update if exists, else insert
        cur = conn.execute("SELECT user_id FROM secrets WHERE user_id = ? LIMIT 1", (user["id"],))
        existing = cur.fetchone()
        if existing:
            with conn:
                conn.execute(
                    "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
                    (req.secret, now_iso, user["id"]),
                )
        else:
            with conn:
                conn.execute(
                    "INSERT INTO secrets (user_id, secret, created_at, updated_at) VALUES (?, ?, ?, ?)",
                    (user["id"], req.secret, now_iso, now_iso),
                )
        return {"message": "Secret has been set successfully"}
    except sqlite3.Error:
        return JSONResponse(status_code=500, content={"message": "An unexpected error occurred"})
    except Exception:
        return JSONResponse(status_code=500, content={"message": "An unexpected error occurred"})
    finally:
        if conn:
            conn.close()


@app.get("/get_secret")
def get_secret(username: str = Query(...), authorization: Optional[str] = Header(default=None)):
    # Authenticate user via Bearer token
    user, error = authenticate(authorization)
    if error:
        return error

    # Authorization check: user can only read their own secret
    if username != user["username"]:
        return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ? LIMIT 1", (user["id"],))
        row = cur.fetchone()
        secret_value = row["secret"] if row else ""
        return {"secret": secret_value}
    except sqlite3.Error:
        return JSONResponse(status_code=500, content={"message": "An unexpected error occurred"})
    except Exception:
        return JSONResponse(status_code=500, content={"message": "An unexpected error occurred"})
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    # Start the web server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)