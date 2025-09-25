import os
import sqlite3
import uvicorn
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from fastapi import FastAPI, Depends, Request
from fastapi import status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import BaseModel, EmailStr, Field, constr
from passlib.hash import pbkdf2_sha256
import jwt  # PyJWT


DB_PATH = "db.sqlite3"
APP = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Security scheme: HTTP Bearer (JWT)
bearer_scheme = HTTPBearer(auto_error=False)

# Read application secret (for JWT signing)
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Fallback to an ephemeral secret for development if not provided
    # For production, always set APP_SECRET.
    APP_SECRET = os.urandom(32).hex()

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


# -------------------- Utility and DB Helpers -------------------- #

def utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def get_db_connection() -> sqlite3.Connection:
    # Create a new connection per operation to avoid threading issues
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Enforce foreign keys and improve concurrency
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
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
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER PRIMARY KEY,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def fetch_one(query: str, params: tuple = ()) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.execute(query, params)
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def execute_query(query: str, params: tuple = ()) -> int:
    conn = get_db_connection()
    try:
        cur = conn.execute(query, params)
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    return fetch_one("SELECT * FROM users WHERE email = ?;", (email,))


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    return fetch_one("SELECT * FROM users WHERE username = ?;", (username,))


def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    return fetch_one("SELECT * FROM users WHERE id = ?;", (user_id,))


def create_user(email: str, username: str, password_hash: str) -> int:
    now = utc_now_iso()
    return execute_query(
        """
        INSERT INTO users (email, username, password_hash, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?);
        """,
        (email, username, password_hash, now, now),
    )


def upsert_secret(user_id: int, secret: str) -> None:
    now = utc_now_iso()
    execute_query(
        """
        INSERT INTO secrets (user_id, secret, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            secret = excluded.secret,
            updated_at = excluded.updated_at;
        """,
        (user_id, secret, now),
    )


def get_secret_by_user_id(user_id: int) -> Optional[str]:
    row = fetch_one("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
    if row:
        return row["secret"]
    return None


# -------------------- Security Helpers -------------------- #

def hash_password(password: str) -> str:
    # PBKDF2-SHA256 provided by passlib; safe default parameters
    return pbkdf2_sha256.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, password_hash)
    except Exception:
        return False


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.now(tz=timezone.utc)
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = now + expires_delta
    to_encode.update({"iat": int(now.timestamp()), "exp": int(expire.timestamp())})
    token = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_access_token(token: str) -> Dict[str, Any]:
    payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
    return payload


async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)) -> sqlite3.Row:
    if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        # Unauthorized - missing or malformed token
        raise StarletteHTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        sub = payload.get("sub")
        username = payload.get("username")
        if sub is None or username is None:
            raise StarletteHTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        user = get_user_by_id(int(sub))
        if user is None or user["username"] != username:
            raise StarletteHTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        return user
    except jwt.ExpiredSignatureError:
        raise StarletteHTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except jwt.InvalidTokenError:
        raise StarletteHTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except Exception:
        # Generic failure
        raise StarletteHTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")


# -------------------- Pydantic Schemas -------------------- #

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., example="newuser@example.com")
    username: constr(strip_whitespace=True, min_length=3, max_length=50) = Field(..., example="user1")
    password: constr(min_length=6, max_length=256) = Field(..., example="newUserPassword")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="user@example.com")
    password: constr(min_length=1) = Field(..., example="mySecretPassword")


class SetSecretRequest(BaseModel):
    username: constr(strip_whitespace=True, min_length=1, max_length=50) = Field(..., example="user1")
    secret: constr(min_length=1, max_length=4096) = Field(..., example="mySecret")


# -------------------- Exception Handlers -------------------- #

@APP.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    # Return a consistent JSON shape with "message"
    return JSONResponse(status_code=exc.status_code, content={"message": str(exc.detail)})


@APP.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Normalize validation errors into 400 with a generic message
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"message": "Invalid request"},
    )


# -------------------- Routes -------------------- #

@APP.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    summary="User registration",
    tags=["Authentication"],
)
async def register(body: RegisterRequest):
    try:
        # Normalize username to prevent weird unicode normalization attacks surface
        username = body.username
        email = body.email.lower()
        if get_user_by_email(email) is not None:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )
        if get_user_by_username(username) is not None:
            # Do not disclose which field is duplicate for privacy
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message": "Email already in use or invalid data"},
            )
        pw_hash = hash_password(body.password)
        create_user(email=email, username=username, password_hash=pw_hash)
        return {"message": "Registration successful"}
    except Exception:
        # Avoid leaking internals; handle rare errors gracefully
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Email already in use or invalid data"},
        )


@APP.post(
    "/login",
    status_code=status.HTTP_200_OK,
    summary="User login",
    tags=["Authentication"],
)
async def login(body: LoginRequest):
    try:
        user = get_user_by_email(body.email.lower())
        if not user or not verify_password(body.password, user["password_hash"]):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid email or password"},
            )
        token_payload = {
            "sub": str(user["id"]),
            "username": user["username"],
        }
        token = create_access_token(token_payload, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        return {"token": token, "message": "Login successful"}
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid email or password"},
        )


@APP.post(
    "/set_secret",
    status_code=status.HTTP_200_OK,
    summary="Set secret",
)
async def set_secret(body: SetSecretRequest, current_user: sqlite3.Row = Depends(get_current_user)):
    try:
        # Authorization: ensure the username in body matches the authenticated user
        if body.username != current_user["username"]:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid authentication token"},
            )
        # Save/Update secret
        upsert_secret(user_id=current_user["id"], secret=body.secret)
        return {"message": "Secret has been set successfully"}
    except StarletteHTTPException:
        raise
    except Exception:
        # Handle unexpected errors without leaking details
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )


@APP.get(
    "/get_secret",
    status_code=status.HTTP_200_OK,
    summary="Get secret",
)
async def get_secret(username: str, current_user: sqlite3.Row = Depends(get_current_user)):
    try:
        # Authorization: ensure the requested username matches the authenticated user
        if username != current_user["username"]:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"message": "Invalid authentication token"},
            )
        secret = get_secret_by_user_id(current_user["id"])
        if secret is None:
            # No secret set yet; return empty string
            return {"secret": ""}
        return {"secret": secret}
    except StarletteHTTPException:
        raise
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authentication token"},
        )


# -------------------- Startup -------------------- #

@APP.on_event("startup")
async def on_startup():
    init_db()


if __name__ == "__main__":
    # Start the web server
    uvicorn.run(APP, host="0.0.0.0", port=5000)