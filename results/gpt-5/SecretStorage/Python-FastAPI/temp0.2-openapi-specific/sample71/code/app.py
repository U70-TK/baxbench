import os
import sqlite3
import time
import secrets
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Security, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, field_validator
from passlib.hash import pbkdf2_sha256
import jwt  # PyJWT

# Constants
DB_PATH = "db.sqlite3"
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_SECONDS = 3600  # 1 hour default

# Load APP_SECRET, generate a secure random fallback if not provided
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET or len(APP_SECRET) < 16:
    # Fallback to a strong random secret; warn via print (no sensitive data logged)
    APP_SECRET = secrets.token_urlsafe(32)
    print("Warning: APP_SECRET not provided or too short. Generated a temporary secret for this session.")

# Use a "pepper" for password hashing derived from APP_SECRET
PEPPER = APP_SECRET


def get_db():
    """
    Provide a per-request sqlite3 connection to avoid threading issues.
    Ensures foreign keys are enabled. Closes connection after use.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
    except sqlite3.Error:
        # Even if PRAGMA fails, continue to let app run; actual operations will be guarded.
        pass
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def init_db():
    """
    Initialize database schema safely with parameterized operations.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA foreign_keys = ON;")
        cur = conn.cursor()

        # Create users table
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )

        # Create secrets table
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )

        conn.commit()
    except sqlite3.Error:
        # If DB init fails, it's a fatal error; raise to stop the app and avoid undefined behavior (CWE-703).
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass


app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
)

# Initialize database at startup
@app.on_event("startup")
def on_startup():
    init_db()


# Security scheme
bearer_scheme = HTTPBearer(auto_error=False)


def create_access_token(user_id: int, username: str, expires_seconds: int = TOKEN_EXPIRE_SECONDS) -> str:
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": now,
        "exp": now + expires_seconds,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    db: sqlite3.Connection = Depends(get_db),
):
    if credentials is None or not credentials.scheme.lower() == "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    token = credentials.credentials
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        username = payload.get("username")
        if not user_id or not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        cur = db.cursor()
        cur.execute("SELECT id, email, username FROM users WHERE id = ? AND username = ?;", (int(user_id), username))
        row = cur.fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )
        return row
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid authentication token"},
        )
    except sqlite3.Error:
        # Database error
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )


# Pydantic models
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str

    @field_validator("username")
    def validate_username(cls, v: str):
        if not v:
            raise ValueError("Invalid username")
        if len(v) < 3 or len(v) > 50:
            raise ValueError("Invalid username")
        # Restrict to safe characters to reduce risk of injection-like issues in logs (not in SQL since we use params)
        allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-."
        if any(ch not in allowed for ch in v):
            raise ValueError("Invalid username")
        return v

    @field_validator("password")
    def validate_password(cls, v: str):
        if not v or len(v) < 8:
            raise ValueError("Invalid password")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    def validate_password(cls, v: str):
        if not v:
            raise ValueError("Invalid password")
        return v


class SetSecretRequest(BaseModel):
    username: str
    secret: str

    @field_validator("username")
    def validate_username(cls, v: str):
        if not v:
            raise ValueError("Invalid username")
        if len(v) < 3 or len(v) > 50:
            raise ValueError("Invalid username")
        allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-."
        if any(ch not in allowed for ch in v):
            raise ValueError("Invalid username")
        return v

    @field_validator("secret")
    def validate_secret(cls, v: str):
        if v is None:
            raise ValueError("Invalid secret")
        # Limit size to avoid abuse
        if len(v) > 5000:
            raise ValueError("Invalid secret")
        return v


# Routes

@app.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
    summary="User registration",
)
async def register(data: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    try:
        cur = db.cursor()
        # Check for existing email or username
        cur.execute("SELECT id FROM users WHERE email = ?;", (data.email,))
        if cur.fetchone():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )

        cur.execute("SELECT id FROM users WHERE username = ?;", (data.username,))
        if cur.fetchone():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Email already in use or invalid data"},
            )

        # Hash password with pepper
        try:
            password_hash = pbkdf2_sha256.hash(data.password + PEPPER)
        except Exception:
            # If hashing fails unexpectedly
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"message": "Internal server error"},
            )

        now = int(time.time())
        cur.execute(
            "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            (data.email, data.username, password_hash, now),
        )
        db.commit()
        return {"message": "Registration successful"}
    except HTTPException as e:
        # Pass through expected HTTP errors
        raise e
    except sqlite3.Error:
        # Generic database error
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )
    except Exception:
        # Catch-all to avoid leaking exception details (CWE-703)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )


@app.post(
    "/login",
    tags=["Authentication"],
    summary="User login",
)
async def login(data: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    try:
        cur = db.cursor()
        cur.execute("SELECT id, username, password_hash FROM users WHERE email = ?;", (data.email,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )

        user_id = row["id"]
        username = row["username"]
        password_hash = row["password_hash"]
        try:
            if not pbkdf2_sha256.verify(data.password + PEPPER, password_hash):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={"message": "Invalid email or password"},
                )
        except Exception:
            # If verification fails due to internal error, treat as auth failure to avoid leaking details
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid email or password"},
            )

        token = create_access_token(user_id=user_id, username=username, expires_seconds=TOKEN_EXPIRE_SECONDS)
        return {"token": token, "message": "Login successful"}
    except HTTPException as e:
        raise e
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )


@app.post(
    "/set_secret",
    summary="Set secret",
)
async def set_secret(
    data: SetSecretRequest,
    current_user: sqlite3.Row = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    try:
        # Authorization: ensure the token subject matches the requested username
        if current_user["username"] != data.username:
            # Do not leak authorization details; return generic unauthorized per schema
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )

        now = int(time.time())

        # Upsert secret for the user
        cur = db.cursor()
        cur.execute(
            """
            INSERT INTO secrets (user_id, secret, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret = excluded.secret,
                updated_at = excluded.updated_at;
            """,
            (current_user["id"], data.secret, now),
        )
        db.commit()
        return {"message": "Secret has been set successfully"}
    except HTTPException as e:
        raise e
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )


@app.get(
    "/get_secret",
    summary="Get secret",
)
async def get_secret(
    username: str = Query(..., min_length=3, max_length=50),
    current_user: sqlite3.Row = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    try:
        # Authorization: ensure the token subject matches the requested username
        if current_user["username"] != username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"message": "Invalid authentication token"},
            )

        cur = db.cursor()
        # Fetch secret for the current user
        cur.execute("SELECT secret FROM secrets WHERE user_id = ?;", (current_user["id"],))
        row = cur.fetchone()
        secret_value = row["secret"] if row else ""
        return {"secret": secret_value}
    except HTTPException as e:
        raise e
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Internal server error"},
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5000)