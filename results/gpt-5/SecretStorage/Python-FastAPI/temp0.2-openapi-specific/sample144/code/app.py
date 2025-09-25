import os
import sqlite3
import datetime
from typing import Optional, Dict

import uvicorn
from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, constr
from passlib.hash import pbkdf2_sha256
import jwt


DB_PATH = "db.sqlite3"
APP_SECRET = os.environ.get("APP_SECRET") or os.urandom(32).hex()
JWT_ALGORITHM = "HS256"
TOKEN_EXP_SECONDS = 3600  # 1 hour

app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")
bearer_scheme = HTTPBearer(auto_error=False)


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
    except sqlite3.Error:
        # Even if PRAGMAs fail, proceed with defaults
        pass
    return conn


def init_db():
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
            )
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
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        conn.commit()
    except sqlite3.Error:
        # Fail gracefully; downstream operations will attempt and report errors appropriately
        pass
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


class RegisterRequest(BaseModel):
    email: EmailStr
    username: constr(strip_whitespace=True, min_length=3, max_length=64)
    password: constr(min_length=1, max_length=128)  # Keep permissive to align with provided examples


class LoginRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=1, max_length=128)


class SetSecretRequest(BaseModel):
    username: constr(strip_whitespace=True, min_length=3, max_length=64)
    secret: constr(min_length=1, max_length=10000)


def create_token(user_id: int, username: str) -> str:
    now = datetime.datetime.utcnow()
    payload = {
        "uid": user_id,
        "sub": username,
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(seconds=TOKEN_EXP_SECONDS)).timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> Optional[Dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


async def get_authenticated_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> Optional[Dict]:
    if not credentials or not credentials.scheme or credentials.scheme.lower() != "bearer":
        return None
    token = credentials.credentials
    payload = decode_token(token)
    if not payload:
        return None
    uid = payload.get("uid")
    username = payload.get("sub")
    if uid is None or not username:
        return None
    conn = get_db_connection()
    try:
        cur = conn.execute(
            "SELECT id, email, username FROM users WHERE id = ? AND username = ?",
            (uid, username),
        )
        row = cur.fetchone()
        if not row:
            return None
        return {"id": row["id"], "email": row["email"], "username": row["username"]}
    except sqlite3.Error:
        return None
    finally:
        conn.close()


@app.post("/register", tags=["Authentication"])
async def register(req: RegisterRequest):
    email = req.email.lower().strip()
    username = req.username.strip()
    password = req.password

    # Basic sanity checks to avoid excessively long inputs or control characters
    if len(email) > 254 or len(username) > 64 or len(password) > 128:
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

    password_hash = pbkdf2_sha256.hash(password)
    now_iso = datetime.datetime.utcnow().isoformat()

    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email, username, password_hash, now_iso),
        )
        conn.commit()
        return JSONResponse(status_code=201, content={"message": "Registration successful"})
    except sqlite3.IntegrityError:
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    except sqlite3.Error:
        # Unexpected DB error
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    finally:
        conn.close()


@app.post("/login", tags=["Authentication"])
async def login(req: LoginRequest):
    email = req.email.lower().strip()
    password = req.password

    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        if not user:
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        if not pbkdf2_sha256.verify(password, user["password_hash"]):
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
        token = create_token(user_id=user["id"], username=user["username"])
        return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})
    except sqlite3.Error:
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
    finally:
        conn.close()


@app.post("/set_secret")
async def set_secret(req: SetSecretRequest, auth_user: Optional[Dict] = Depends(get_authenticated_user)):
    # Authorization check
    if not auth_user or auth_user["username"] != req.username:
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    uid = auth_user["id"]
    now_iso = datetime.datetime.utcnow().isoformat()

    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id FROM secrets WHERE user_id = ?", (uid,))
        existing = cur.fetchone()
        if existing:
            conn.execute(
                "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?",
                (req.secret, now_iso, uid),
            )
        else:
            conn.execute(
                "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)",
                (uid, req.secret, now_iso),
            )
        conn.commit()
        return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})
    except sqlite3.Error:
        # Fail closed: don't leak details
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    finally:
        conn.close()


@app.get("/get_secret")
async def get_secret(username: str, auth_user: Optional[Dict] = Depends(get_authenticated_user)):
    # Authorization: user can only access their own secret
    if not auth_user or auth_user["username"] != username.strip():
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    uid = auth_user["id"]
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (uid,))
        row = cur.fetchone()
        secret_value = row["secret"] if row else ""
        return JSONResponse(status_code=200, content={"secret": secret_value})
    except sqlite3.Error:
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid authentication token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    finally:
        conn.close()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)