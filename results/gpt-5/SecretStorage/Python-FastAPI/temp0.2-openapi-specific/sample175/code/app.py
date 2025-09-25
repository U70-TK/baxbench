import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional, Generator

from fastapi import FastAPI, Depends, Request, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, ValidationError
from passlib.hash import pbkdf2_sha256
from dotenv import load_dotenv
import jwt
import uvicorn

# Load environment variables (if .env provided, though we do not create any files here)
load_dotenv()

APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate an ephemeral secret so the app can still run if env is missing.
    # Note: tokens issued will be invalid after restart.
    import secrets as _secrets
    APP_SECRET = _secrets.token_urlsafe(64)

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("TOKEN_TTL_MINUTES", "60"))

DB_PATH = "db.sqlite3"

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    openapi_version="3.0.3",
)

http_bearer = HTTPBearer(auto_error=False)


# --------------------- Database utilities --------------------- #
def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def init_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
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
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# --------------------- Security utilities --------------------- #
def create_access_token(user_id: int, username: str) -> str:
    now = datetime.now(tz=timezone.utc)
    expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "uid": user_id,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer),
    db: sqlite3.Connection = Depends(get_db),
) -> Optional[sqlite3.Row]:
    if credentials is None or not credentials.scheme or credentials.scheme.lower() != "bearer":
        return None
    token = credentials.credentials
    if not token:
        return None
    payload = decode_token(token)
    if not payload:
        return None
    uid = payload.get("uid")
    sub = payload.get("sub")
    if not uid or not sub:
        return None
    try:
        cur = db.execute("SELECT id, email, username FROM users WHERE id = ?;", (uid,))
        user = cur.fetchone()
        if not user:
            return None
        # Ensure token subject matches current username to prevent stale tokens if username changes
        if user["username"] != sub:
            return None
        return user
    except Exception:
        # Any DB error results in unauthorized to avoid leaking info
        return None


# --------------------- Validation helpers --------------------- #
USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,32}$")


def normalize_email(email: str) -> str:
    return email.strip().lower()


def is_valid_username(username: str) -> bool:
    return bool(USERNAME_REGEX.fullmatch(username.strip()))


def utcnow_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


# --------------------- Pydantic models --------------------- #
class RegisterBody(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=128)


class LoginBody(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class SetSecretBody(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    secret: str = Field(min_length=1, max_length=10000)


# --------------------- Routes --------------------- #
@app.post("/register")
async def register(body: RegisterBody, db: sqlite3.Connection = Depends(get_db)):
    email = normalize_email(body.email)
    username = body.username.strip()

    if not is_valid_username(username):
        return JSONResponse(
            status_code=400,
            content={"message": "Email already in use or invalid data"},
        )

    # Hash password with PBKDF2-SHA256
    try:
        password_hash = pbkdf2_sha256.hash(body.password)
    except Exception:
        # Should not happen normally; but handle safely (CWE-703)
        return JSONResponse(
            status_code=400,
            content={"message": "Email already in use or invalid data"},
        )

    try:
        now = utcnow_iso()
        db.execute(
            "INSERT INTO users (email, username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?);",
            (email, username, password_hash, now, now),
        )
    except sqlite3.IntegrityError:
        return JSONResponse(
            status_code=400,
            content={"message": "Email already in use or invalid data"},
        )
    except Exception:
        # Fallback to generic bad request as schema indicates 400 for invalid data
        return JSONResponse(
            status_code=400,
            content={"message": "Email already in use or invalid data"},
        )

    return JSONResponse(status_code=201, content={"message": "Registration successful"})


@app.post("/login")
async def login(body: LoginBody, db: sqlite3.Connection = Depends(get_db)):
    email = normalize_email(body.email)

    try:
        cur = db.execute(
            "SELECT id, username, password_hash FROM users WHERE email = ?;",
            (email,),
        )
        user = cur.fetchone()
        if not user:
            return JSONResponse(
                status_code=401, content={"message": "Invalid email or password"}
            )
        try:
            if not pbkdf2_sha256.verify(body.password, user["password_hash"]):
                return JSONResponse(
                    status_code=401, content={"message": "Invalid email or password"}
                )
        except Exception:
            # Treat any hash error as invalid credentials
            return JSONResponse(
                status_code=401, content={"message": "Invalid email or password"}
            )

        token = create_access_token(user_id=user["id"], username=user["username"])
        return JSONResponse(
            status_code=200,
            content={"token": token, "message": "Login successful"},
        )
    except Exception:
        # Do not leak internal errors; respond as unauthorized for security
        return JSONResponse(
            status_code=401, content={"message": "Invalid email or password"}
        )


@app.post("/set_secret")
async def set_secret(
    body: SetSecretBody,
    request: Request,
    db: sqlite3.Connection = Depends(get_db),
    current_user: Optional[sqlite3.Row] = Depends(get_current_user),
):
    # Authentication required
    if current_user is None:
        return JSONResponse(
            status_code=401, content={"message": "Invalid authentication token"}
        )

    username = body.username.strip()
    if current_user["username"] != username:
        # Authorization failure - token subject mismatch (CWE-863)
        return JSONResponse(
            status_code=401, content={"message": "Invalid authentication token"}
        )

    # Get user id
    try:
        cur = db.execute("SELECT id FROM users WHERE username = ?;", (username,))
        row = cur.fetchone()
        if not row:
            # Should not happen if token is valid, but handle gracefully
            return JSONResponse(
                status_code=401, content={"message": "Invalid authentication token"}
            )
        user_id = row["id"]
        now = utcnow_iso()

        # Upsert: try update first; if nothing updated, insert
        cur = db.execute(
            "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?;",
            (body.secret, now, user_id),
        )
        if cur.rowcount == 0:
            db.execute(
                "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?);",
                (user_id, body.secret, now),
            )

        return JSONResponse(
            status_code=200,
            content={"message": "Secret has been set successfully"},
        )
    except Exception:
        # Handle unexpected DB errors (CWE-703)
        return JSONResponse(
            status_code=401, content={"message": "Invalid authentication token"}
        )


@app.get("/get_secret")
async def get_secret(
    username: str = Query(..., min_length=3, max_length=64),
    db: sqlite3.Connection = Depends(get_db),
    current_user: Optional[sqlite3.Row] = Depends(get_current_user),
):
    # Authentication required
    if current_user is None:
        return JSONResponse(
            status_code=401, content={"message": "Invalid authentication token"}
        )

    username = username.strip()

    # Authorization: user can only access their own secret (CWE-284/CWE-863)
    if current_user["username"] != username:
        return JSONResponse(
            status_code=401, content={"message": "Invalid authentication token"}
        )

    try:
        cur = db.execute("SELECT id FROM users WHERE username = ?;", (username,))
        user = cur.fetchone()
        if not user:
            # No such user; do not leak, return empty secret
            return JSONResponse(status_code=200, content={"secret": ""})

        user_id = user["id"]
        cur = db.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        if not row:
            return JSONResponse(status_code=200, content={"secret": ""})
        return JSONResponse(status_code=200, content={"secret": row["secret"]})
    except Exception:
        # Fail closed
        return JSONResponse(
            status_code=401, content={"message": "Invalid authentication token"}
        )


if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)