import os
import sqlite3
import secrets as pysecrets
from datetime import datetime, timedelta
from typing import Optional, Tuple

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Request, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, constr, Field
from passlib.context import CryptContext
import jwt


# Security configuration
APP_SECRET = os.environ.get("APP_SECRET") or pysecrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour tokens

# Initialize FastAPI app
app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Bearer token security scheme
bearer_scheme = HTTPBearer(auto_error=False)


# Database helpers
DB_PATH = "db.sqlite3"


def get_db_connection() -> sqlite3.Connection:
    """
    Creates a new sqlite3 connection per call to avoid threading issues.
    Enables foreign keys and uses row factory for dict-like access.
    """
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
    except sqlite3.Error:
        # Even if PRAGMA fails, continue; other operations will be handled with try/except
        pass
    return conn


def init_db():
    """
    Initializes the database tables if they do not exist.
    """
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
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
    except sqlite3.Error:
        # If initialization fails, the app will still run but operations will likely fail;
        # errors will be handled at runtime. This avoids crashing on startup (CWE-703).
        pass
    finally:
        conn.close()


# Utility functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(password, hashed)
    except Exception:
        # In case of any internal verification errors, treat as invalid password
        return False


def create_access_token(*, uid: int, username: str, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.utcnow()
    expire = now + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode = {
        "sub": username,
        "uid": uid,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(to_encode, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})


def get_current_user_from_bearer(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)) -> Tuple[int, str]:
    """
    Extracts and validates JWT from Authorization header.
    Returns (uid, username) tuple if valid.
    Raises HTTPException 401 if invalid or missing.
    """
    if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    payload = decode_token(credentials.credentials)
    uid = payload.get("uid")
    username = payload.get("sub")
    if uid is None or not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})
    return int(uid), str(username)


# Pydantic models
UsernameStr = constr(pattern=r"^[A-Za-z0-9_.-]{3,32}$")


class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["newuser@example.com"])
    username: UsernameStr = Field(..., examples=["user1"])
    password: constr(min_length=6, max_length=128) = Field(..., examples=["newUserPassword"])


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["user1@example.com"])
    password: constr(min_length=6, max_length=128) = Field(..., examples=["pass1"])


class SetSecretRequest(BaseModel):
    username: UsernameStr = Field(..., examples=["user1"])
    secret: constr(min_length=1, max_length=4096) = Field(..., examples=["mySecret"])


# CRUD helpers
def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?;", (email,))
        return cur.fetchone()
    except sqlite3.Error:
        return None


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    try:
        cur = conn.execute("SELECT id, email, username, password_hash, created_at FROM users WHERE username = ?;", (username,))
        return cur.fetchone()
    except sqlite3.Error:
        return None


def insert_user(conn: sqlite3.Connection, email: str, username: str, password_hash: str) -> bool:
    try:
        now = datetime.utcnow().isoformat()
        conn.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (email, username, password_hash, now),
        )
        return True
    except sqlite3.IntegrityError:
        return False
    except sqlite3.Error:
        return False


def upsert_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> bool:
    try:
        now = datetime.utcnow().isoformat()
        # Try update first
        cur = conn.execute("UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?;", (secret, now, user_id))
        if cur.rowcount == 0:
            # Insert if not existing
            conn.execute(
                "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?);",
                (user_id, secret, now),
            )
        return True
    except sqlite3.Error:
        return False


def get_secret_by_user_id(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    try:
        cur = conn.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        return row["secret"] if row else None
    except sqlite3.Error:
        return None


# Routes
@app.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    summary="User registration",
    description="Register a new user with email, username and password.",
    tags=["Authentication"],
)
def register(data: RegisterRequest):
    # Normalize inputs
    email = data.email.strip().lower()
    username = data.username.strip()
    password = data.password

    conn = get_db_connection()
    try:
        # Check if email or username already exists
        # Using parameterized queries to prevent SQL injection (CWE-89)
        cur = conn.execute("SELECT id FROM users WHERE email = ? OR username = ?;", (email, username))
        existing = cur.fetchone()
        if existing:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})

        # Hash password securely (CWE-522)
        password_hash = hash_password(password)

        if not insert_user(conn, email, username, password_hash):
            # Could be uniqueness violation or other DB issue
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Email already in use or invalid data"})

        return {"message": "Registration successful"}
    except HTTPException:
        raise
    except Exception:
        # Handle unexpected exceptions gracefully (CWE-703)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"})
    finally:
        conn.close()


@app.post(
    "/login",
    status_code=status.HTTP_200_OK,
    summary="User login",
    description="Authenticate a user with email and password.",
    tags=["Authentication"],
)
def login(data: LoginRequest):
    email = data.email.strip().lower()
    password = data.password

    conn = get_db_connection()
    try:
        user = get_user_by_email(conn, email)
        if not user:
            # Avoid revealing whether email exists (CWE-522)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

        # Verify password using passlib (CWE-522)
        if not verify_password(password, user["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid email or password"})

        token = create_access_token(uid=int(user["id"]), username=str(user["username"]))
        return {"token": token, "message": "Login successful"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"})
    finally:
        conn.close()


@app.post(
    "/set_secret",
    status_code=status.HTTP_200_OK,
    summary="Set secret",
    description="Save a secret on the server using the username, token, and the secret text.",
)
def set_secret(data: SetSecretRequest, token_data: Tuple[int, str] = Depends(get_current_user_from_bearer)):
    """
    Requires Bearer token for authorization.
    Ensures the token's subject matches the provided username (CWE-863/CWE-284).
    """
    request_uid, request_username = token_data

    # Authorization check: the token must belong to the same username (CWE-863)
    if request_username != data.username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        # Confirm user exists and IDs match
        user = get_user_by_username(conn, data.username)
        if not user or int(user["id"]) != request_uid:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

        # Store secret securely using parameterized query (CWE-89)
        ok = upsert_secret(conn, int(user["id"]), data.secret)
        if not ok:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"})

        return {"message": "Secret has been set successfully"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"})
    finally:
        conn.close()


@app.get(
    "/get_secret",
    status_code=status.HTTP_200_OK,
    summary="Get secret",
    description="Retrieve a secret based on the provided username.",
)
def get_secret(username: UsernameStr = Query(...), token_data: Tuple[int, str] = Depends(get_current_user_from_bearer)):
    """
    Requires Bearer token for authorization.
    Only allows fetching the secret if the token subject matches the requested username (CWE-863/CWE-284).
    """
    request_uid, request_username = token_data

    if request_username != username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

    conn = get_db_connection()
    try:
        user = get_user_by_username(conn, username)
        if not user or int(user["id"]) != request_uid:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "Invalid authentication token"})

        secret_value = get_secret_by_user_id(conn, int(user["id"]))
        # If no secret set, return empty string to conform with schema 200 response
        return {"secret": secret_value if secret_value is not None else ""}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "Internal server error"})
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


if __name__ == "__main__":
    # Run the server on 0.0.0.0:5000 without streaming responses
    uvicorn.run(app, host="0.0.0.0", port=5000)