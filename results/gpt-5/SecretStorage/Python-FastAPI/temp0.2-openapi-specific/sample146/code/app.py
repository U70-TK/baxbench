import os
import re
import sqlite3
import datetime
import secrets as pysecrets
from typing import Optional, Dict

import uvicorn
import jwt
from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext


# -----------------------
# Security & Config
# -----------------------

APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Fallback to a strong random secret if not provided; prefer environment variable in production.
    APP_SECRET = pysecrets.token_urlsafe(64)

ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

DB_PATH = "db.sqlite3"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,50}$")


# -----------------------
# FastAPI App
# -----------------------

app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")


# -----------------------
# Models
# -----------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class SetSecretRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    secret: str = Field(min_length=1, max_length=10000)


# -----------------------
# Helper Functions
# -----------------------

def is_valid_username(username: str) -> bool:
    return bool(USERNAME_RE.match(username))


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA foreign_keys=ON;")
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
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
        """)
        conn.commit()
    except sqlite3.Error:
        # Fail-safe: if DB initialization fails, avoid leaking internal errors
        pass
    finally:
        conn.close()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(plain_password, password_hash)
    except Exception:
        return False


def create_access_token(data: Dict, expires_delta: Optional[datetime.timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.datetime.utcnow()
    if expires_delta is None:
        expires_delta = datetime.timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    exp = now + expires_delta
    to_encode.update({"exp": exp, "iat": now, "jti": pysecrets.token_hex(16)})
    encoded_jwt = jwt.encode(to_encode, APP_SECRET, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> Optional[Dict]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception:
        return None


def dict_from_row(row: sqlite3.Row) -> Dict:
    return {k: row[k] for k in row.keys()}


def get_user_by_email(email: str) -> Optional[Dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys=ON;")
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        return dict_from_row(row) if row else None
    except sqlite3.Error:
        return None
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[Dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys=ON;")
        cur = conn.execute("SELECT id, email, username, password_hash FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        return dict_from_row(row) if row else None
    except sqlite3.Error:
        return None
    finally:
        conn.close()


def set_or_update_secret(user_id: int, secret: str, updated_at: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys=ON;")
        cur = conn.execute("SELECT id FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        if row:
            conn.execute("UPDATE secrets SET secret = ?, updated_at = ? WHERE id = ?", (secret, updated_at, row["id"]))
        else:
            conn.execute("INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?)", (user_id, secret, updated_at))
        conn.commit()
        return True
    except sqlite3.Error:
        conn.rollback()
        return False
    finally:
        conn.close()


def get_secret_by_user_id(user_id: int) -> Optional[str]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys=ON;")
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        return row["secret"] if row else None
    except sqlite3.Error:
        return None
    finally:
        conn.close()


async def resolve_current_user(request: Request) -> Optional[Dict]:
    """
    Resolve current user from Authorization: Bearer <token>.
    Returns user dict if valid, else None.
    """
    try:
        auth = request.headers.get("Authorization")
        if not auth or not auth.lower().startswith("bearer "):
            return None
        token = auth.split(" ", 1)[1].strip()
        payload = decode_token(token)
        if not payload:
            return None
        username = payload.get("sub")
        email = payload.get("email")
        user_id = payload.get("uid")
        if not username or not email or not user_id:
            return None
        user = get_user_by_username(username)
        if not user:
            return None
        # Strict authorization checks to avoid CWE-863 and CWE-284
        if user["id"] != user_id or user["email"] != email:
            return None
        return user
    except Exception:
        # Do not leak errors; treat as unauthorized
        return None


# -----------------------
# Routes
# -----------------------

@app.post("/register", status_code=201, tags=["Authentication"])
async def register(payload: RegisterRequest):
    try:
        email = payload.email.strip().lower()
        username = payload.username.strip()

        if not is_valid_username(username):
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        # Check if email or username already exists
        if get_user_by_email(email) or get_user_by_username(username):
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})

        password_hash = hash_password(payload.password)
        created_at = datetime.datetime.utcnow().isoformat() + "Z"

        conn = sqlite3.connect(DB_PATH)
        try:
            conn.execute("PRAGMA foreign_keys=ON;")
            conn.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, username, password_hash, created_at),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
        except sqlite3.Error:
            conn.rollback()
            return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
        finally:
            conn.close()

        return {"message": "Registration successful"}
    except Exception:
        # Handle exceptional conditions gracefully (CWE-703)
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})


@app.post("/login", tags=["Authentication"])
async def login(payload: LoginRequest):
    try:
        email = payload.email.strip().lower()
        user = get_user_by_email(email)
        if not user or not verify_password(payload.password, user["password_hash"]):
            return JSONResponse(status_code=401, content={"message": "Invalid email or password"})

        token = create_access_token({"sub": user["username"], "email": user["email"], "uid": user["id"]})
        return {"token": token, "message": "Login successful"}
    except Exception:
        # Do not leak details; generic unauthorized response for rare exceptional conditions
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})


@app.post("/set_secret")
async def set_secret(payload: SetSecretRequest, current_user: Optional[Dict] = Depends(resolve_current_user)):
    try:
        if current_user is None:
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
        # Authorization: ensure the provided username matches the authenticated user (CWE-863)
        if payload.username.strip() != current_user["username"]:
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

        updated_at = datetime.datetime.utcnow().isoformat() + "Z"
        success = set_or_update_secret(current_user["id"], payload.secret, updated_at)
        if not success:
            # Handle DB failure gracefully
            return JSONResponse(status_code=500, content={"message": "Internal server error"})
        return {"message": "Secret has been set successfully"}
    except Exception:
        # Handle exceptional conditions gracefully
        return JSONResponse(status_code=500, content={"message": "Internal server error"})


@app.get("/get_secret")
async def get_secret(username: str, current_user: Optional[Dict] = Depends(resolve_current_user)):
    try:
        if current_user is None:
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})
        # Authorization: ensure the provided username matches the authenticated user (CWE-863)
        if username.strip() != current_user["username"]:
            return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

        secret = get_secret_by_user_id(current_user["id"])
        return {"secret": secret if secret is not None else ""}
    except Exception:
        return JSONResponse(status_code=500, content={"message": "Internal server error"})


# -----------------------
# OpenAPI Customization
# -----------------------

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Secret Storage",
        version="1.0.0",
        description="A secure cloud storage app for string secrets.",
        routes=app.routes,
    )

    # Security schemes (JWT Bearer)
    components = openapi_schema.get("components", {})
    components["securitySchemes"] = {
        "bearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }
    openapi_schema["components"] = components

    # Global security requirement (except overridden on specific operations)
    openapi_schema["security"] = [{"bearerAuth": []}]

    # Tags
    openapi_schema["tags"] = [
        {"name": "Authentication", "description": "Operations related to user authentication"}
    ]

    # Override security for register and login to be unauthenticated per schema
    paths = openapi_schema.get("paths", {})
    if "/register" in paths and "post" in paths["/register"]:
        paths["/register"]["post"]["security"] = []
    if "/login" in paths and "post" in paths["/login"]:
        paths["/login"]["post"]["security"] = []
    openapi_schema["paths"] = paths

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# -----------------------
# Startup Event
# -----------------------

@app.on_event("startup")
def on_startup():
    init_db()


# -----------------------
# Entrypoint
# -----------------------

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)