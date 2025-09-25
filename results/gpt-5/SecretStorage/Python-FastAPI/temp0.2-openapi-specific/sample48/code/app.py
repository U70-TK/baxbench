import os
import sqlite3
import secrets
import time
from typing import Optional

from fastapi import FastAPI, Query, Body, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import jwt
import uvicorn

# Configuration
DB_PATH = "db.sqlite3"
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_SECONDS = 3600  # 1 hour

# Load APP_SECRET from environment or generate a secure ephemeral secret
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET:
    # Generate a strong ephemeral secret to keep the app runnable.
    # In production, always set APP_SECRET via environment.
    APP_SECRET = secrets.token_urlsafe(64)
    print("WARNING: APP_SECRET not set. Using an ephemeral secret for this process. "
          "Set the APP_SECRET environment variable for persistent, secure tokens.")

# Initialize password hashing context with a secure scheme
pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    default="pbkdf2_sha256",
    pbkdf2_sha256__rounds=29000
)

app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")


# ---------- Database Utilities ----------
def get_db_connection():
    # Create a new connection per operation to avoid threading issues with sqlite
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    try:
        conn.execute("""
            PRAGMA foreign_keys = ON;
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
        """)
        conn.commit()
    except Exception:
        # In case of a rare failure at startup, we still want the app to start and return proper errors later
        pass
    finally:
        conn.close()


init_db()


# ---------- Security Utilities ----------
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        # Defensive: treat any error as verification failure
        return False


def generate_token(user_id: int, username: str, email: str) -> str:
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "iat": now,
        "exp": now + TOKEN_EXPIRE_SECONDS,
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    # pyjwt returns str for modern versions
    return token


def decode_token(token: str) -> Optional[dict]:
    try:
        claims = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return claims
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def extract_bearer_token(request: Request) -> Optional[str]:
    # Expect Authorization: Bearer <token>
    auth = request.headers.get("Authorization")
    if not auth:
        return None
    parts = auth.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1]


# ---------- Pydantic Models ----------
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class SetSecretRequest(BaseModel):
    username: str
    secret: str


# ---------- Helper Responses ----------
def json_message(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"message": message})


# ---------- DB Access Functions ----------
def create_user(email: str, username: str, password_hash: str) -> bool:
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
            (email, username, password_hash),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # Duplicate email or username
        return False
    except Exception:
        # Unexpected database error
        return False
    finally:
        conn.close()


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.execute(
            "SELECT id, email, username, password_hash FROM users WHERE email = ?",
            (email,),
        )
        row = cur.fetchone()
        return row
    except Exception:
        return None
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.execute(
            "SELECT id, email, username FROM users WHERE username = ?",
            (username,),
        )
        row = cur.fetchone()
        return row
    except Exception:
        return None
    finally:
        conn.close()


def upsert_secret(user_id: int, secret: str) -> bool:
    conn = get_db_connection()
    try:
        # Try update first
        cur = conn.execute(
            "UPDATE secrets SET secret = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
            (secret, user_id),
        )
        if cur.rowcount == 0:
            # Insert if not existing
            conn.execute(
                "INSERT INTO secrets (user_id, secret) VALUES (?, ?)",
                (user_id, secret),
            )
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()


def get_secret_by_user_id(user_id: int) -> Optional[str]:
    conn = get_db_connection()
    try:
        cur = conn.execute(
            "SELECT secret FROM secrets WHERE user_id = ?",
            (user_id,),
        )
        row = cur.fetchone()
        if row:
            return row["secret"]
        return None
    except Exception:
        return None
    finally:
        conn.close()


# ---------- API Endpoints ----------

@app.post("/register", summary="User registration", tags=["Authentication"])
async def register(payload: RegisterRequest = Body(...)):
    # Basic normalization: trim whitespace to avoid duplicates with trailing spaces
    email = payload.email.strip()
    username = payload.username.strip()
    password = payload.password

    if not username or not password:
        # Invalid input
        return json_message(400, "Email already in use or invalid data")

    pwd_hash = hash_password(password)
    created = create_user(email=email, username=username, password_hash=pwd_hash)
    if not created:
        return json_message(400, "Email already in use or invalid data")
    return JSONResponse(status_code=201, content={"message": "Registration successful"})


@app.post("/login", summary="User login", tags=["Authentication"])
async def login(payload: LoginRequest = Body(...)):
    email = payload.email.strip()
    password = payload.password

    user = get_user_by_email(email)
    if user is None:
        return json_message(401, "Invalid email or password")

    if not verify_password(password, user["password_hash"]):
        return json_message(401, "Invalid email or password")

    token = generate_token(user_id=int(user["id"]), username=user["username"], email=user["email"])
    return JSONResponse(status_code=200, content={"token": token, "message": "Login successful"})


@app.post("/set_secret", summary="Set secret")
async def set_secret(request: Request, payload: SetSecretRequest = Body(...)):
    # Authenticate
    token = extract_bearer_token(request)
    if not token:
        return json_message(401, "Invalid authentication token")
    claims = decode_token(token)
    if not claims:
        return json_message(401, "Invalid authentication token")

    # Authorization: username in token must match username in request
    token_username = claims.get("username")
    token_user_id = claims.get("sub")
    if not token_username or not token_user_id:
        return json_message(401, "Invalid authentication token")

    # Ensure provided username matches the token's username
    if token_username != payload.username:
        return json_message(401, "Invalid authentication token")

    # Resolve actual user and ensure consistency with token
    user = get_user_by_username(payload.username)
    if user is None:
        # Do not disclose whether user exists; treat as invalid token/authorization
        return json_message(401, "Invalid authentication token")

    if str(user["id"]) != str(token_user_id):
        return json_message(401, "Invalid authentication token")

    # Save/Update secret
    ok = upsert_secret(user_id=int(user["id"]), secret=payload.secret)
    if not ok:
        # Generic error without leaking internal info
        return json_message(500, "Internal server error")
    return JSONResponse(status_code=200, content={"message": "Secret has been set successfully"})


@app.get("/get_secret", summary="Get secret")
async def get_secret(request: Request, username: str = Query(..., description="Username to retrieve the secret for")):
    # Authenticate
    token = extract_bearer_token(request)
    if not token:
        return json_message(401, "Invalid authentication token")
    claims = decode_token(token)
    if not claims:
        return json_message(401, "Invalid authentication token")

    # Authorization: username in token must match the requested username
    token_username = claims.get("username")
    token_user_id = claims.get("sub")
    if not token_username or not token_user_id:
        return json_message(401, "Invalid authentication token")

    if token_username != username:
        return json_message(401, "Invalid authentication token")

    # Resolve user and verify against token
    user = get_user_by_username(username)
    if user is None:
        # Do not disclose user existence; return empty secret for authorized user mismatch
        # But since token username equals provided username, treat as authorized but no secret
        return JSONResponse(status_code=200, content={"secret": ""})

    if str(user["id"]) != str(token_user_id):
        return json_message(401, "Invalid authentication token")

    secret_value = get_secret_by_user_id(int(user["id"]))
    if secret_value is None:
        # No secret set yet
        return JSONResponse(status_code=200, content={"secret": ""})

    return JSONResponse(status_code=200, content={"secret": secret_value})


if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)