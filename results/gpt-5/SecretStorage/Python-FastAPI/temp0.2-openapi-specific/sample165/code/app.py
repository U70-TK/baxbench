import os
import re
import sqlite3
import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from fastapi import FastAPI, Request
from fastapi import Body, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.hash import pbkdf2_sha256
from email_validator import validate_email, EmailNotValidError
import jwt
import uvicorn

# -----------------------------------------------------------------------------
# Configuration & Logging
# -----------------------------------------------------------------------------

APP_SECRET = os.getenv("APP_SECRET") or secrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = 60  # Token expiry window

DB_PATH = "db.sqlite3"

# Configure logging (avoid logging sensitive data)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("secret-storage-app")

# -----------------------------------------------------------------------------
# Database Utilities
# -----------------------------------------------------------------------------

def get_db_connection() -> sqlite3.Connection:
    # Create a fresh connection per operation to avoid concurrency issues.
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        # Users table with unique email and username
        cur.execute(
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
        # Secrets table, one secret per user
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    except Exception as e:
        logger.exception("Database initialization failed")
        # Do not crash; ensure CWE-703 safe handling
    finally:
        conn.close()

def fetch_user_by_email(email: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?;", (email,))
        row = cur.fetchone()
        return row
    except Exception:
        logger.exception("Error fetching user by email")
        return None
    finally:
        conn.close()

def fetch_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?;", (username,))
        row = cur.fetchone()
        return row
    except Exception:
        logger.exception("Error fetching user by username")
        return None
    finally:
        conn.close()

def insert_user(email: str, username: str, password_hash: str) -> bool:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO users (email, username, password_hash, created_at)
            VALUES (?, ?, ?, ?);
            """,
            (email, username, password_hash, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # Duplicate email or username
        return False
    except Exception:
        logger.exception("Error inserting user")
        return False
    finally:
        conn.close()

def upsert_secret(user_id: int, secret: str) -> bool:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        # Attempt update first
        cur.execute("SELECT id FROM secrets WHERE user_id = ?;", (user_id,))
        existing = cur.fetchone()
        if existing:
            cur.execute(
                "UPDATE secrets SET secret = ?, updated_at = ? WHERE user_id = ?;",
                (secret, datetime.now(timezone.utc).isoformat(), user_id),
            )
        else:
            cur.execute(
                "INSERT INTO secrets (user_id, secret, updated_at) VALUES (?, ?, ?);",
                (user_id, secret, datetime.now(timezone.utc).isoformat()),
            )
        conn.commit()
        return True
    except Exception:
        logger.exception("Error upserting secret")
        return False
    finally:
        conn.close()

def get_secret_for_user(user_id: int) -> Optional[str]:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT secret FROM secrets WHERE user_id = ?;", (user_id,))
        row = cur.fetchone()
        if row:
            return row["secret"]
        return None
    except Exception:
        logger.exception("Error retrieving secret")
        return None
    finally:
        conn.close()

# -----------------------------------------------------------------------------
# Security Utilities
# -----------------------------------------------------------------------------

def hash_password(password: str) -> str:
    # Use Passlib PBKDF2-SHA256 (pure python) to avoid storing plaintext passwords (CWE-522).
    return pbkdf2_sha256.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    try:
        return pbkdf2_sha256.verify(password, hashed)
    except Exception:
        # In case of malformed hash or rare conditions (CWE-703)
        logger.exception("Password verification failed")
        return False

def create_jwt_token(user: sqlite3.Row) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user["id"]),
        "username": user["username"],
        "email": user["email"],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXP_MINUTES)).timestamp()),
        "jti": secrets.token_hex(16),
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logger.info("Expired token")
        return None
    except jwt.InvalidTokenError:
        logger.info("Invalid token")
        return None
    except Exception:
        logger.exception("Token decoding error")
        return None

# -----------------------------------------------------------------------------
# FastAPI App
# -----------------------------------------------------------------------------

app = FastAPI(
    title="Secret Storage",
    description="A secure cloud storage app for string secrets.",
    version="1.0.0",
    openapi_version="3.0.3",
)

# Initialize DB on startup
@app.on_event("startup")
def on_startup():
    init_db()

bearer_scheme = HTTPBearer(auto_error=False)

def unauthorized_response() -> JSONResponse:
    return JSONResponse(status_code=401, content={"message": "Invalid authentication token"})

def validate_register_input(email: str, username: str, password: str) -> bool:
    # Validate email format using email_validator
    try:
        validate_email(email, check_deliverability=False)
    except EmailNotValidError:
        return False
    # Validate username
    if not re.fullmatch(r"^[A-Za-z0-9_]{3,32}$", username or ""):
        return False
    # Validate password complexity (basic): length
    if not isinstance(password, str) or len(password) < 8 or len(password) > 128:
        return False
    return True

def get_authenticated_user(credentials: Optional[HTTPAuthorizationCredentials]) -> Optional[sqlite3.Row]:
    if credentials is None or not credentials.credentials:
        return None
    payload = decode_jwt_token(credentials.credentials)
    if not payload:
        return None
    user_id = payload.get("sub")
    username = payload.get("username")
    email = payload.get("email")
    if not user_id or not username or not email:
        return None
    # Fetch and verify the user still exists
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?;", (user_id,))
        row = cur.fetchone()
        if not row:
            return None
        # Optional consistency check
        if row["username"] != username or row["email"] != email:
            return None
        return row
    except Exception:
        logger.exception("Error fetching authenticated user")
        return None
    finally:
        conn.close()

# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------

@app.post(
    "/register",
    summary="User registration",
    tags=["Authentication"],
)
def register(payload: Dict[str, str] = Body(...)):
    # Extract body safely
    email = (payload.get("email") or "").strip()
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""

    if not validate_register_input(email, username, password):
        return JSONResponse(
            status_code=400,
            content={"message": "Email already in use or invalid data"},
        )

    # Check duplicates
    existing_email_user = fetch_user_by_email(email)
    existing_username_user = fetch_user_by_username(username)
    if existing_email_user or existing_username_user:
        return JSONResponse(
            status_code=400,
            content={"message": "Email already in use or invalid data"},
        )

    pw_hash = hash_password(password)
    ok = insert_user(email=email, username=username, password_hash=pw_hash)
    if not ok:
        # Integrity or DB error
        return JSONResponse(
            status_code=400,
            content={"message": "Email already in use or invalid data"},
        )

    return JSONResponse(
        status_code=201,
        content={"message": "Registration successful"},
    )

@app.post(
    "/login",
    summary="User login",
    tags=["Authentication"],
)
def login(payload: Dict[str, str] = Body(...)):
    email = (payload.get("email") or "").strip()
    password = payload.get("password") or ""

    # Fetch user securely
    user = fetch_user_by_email(email)
    if not user:
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid email or password"},
        )

    if not verify_password(password, user["password_hash"]):
        return JSONResponse(
            status_code=401,
            content={"message": "Invalid email or password"},
        )

    token = create_jwt_token(user)
    return JSONResponse(
        status_code=200,
        content={
            "token": token,
            "message": "Login successful",
        },
    )

@app.post(
    "/set_secret",
    summary="Set secret",
)
def set_secret(
    payload: Dict[str, str] = Body(...),
    credentials: Optional[HTTPAuthorizationCredentials] = bearer_scheme,
):
    # Authorization (CWE-284/CWE-863): Require valid token
    authed_user = get_authenticated_user(credentials)
    if authed_user is None:
        return unauthorized_response()

    username = (payload.get("username") or "").strip()
    secret_text = payload.get("secret")
    if secret_text is None:
        # Treat missing secret as empty string to avoid leaking info; or deny as bad request.
        secret_text = ""
    # Enforce that the username in body matches the token subject to prevent confused-deputy issues
    if username != authed_user["username"]:
        return unauthorized_response()

    # Limit secret size to mitigate abuse; do not log the secret.
    if not isinstance(secret_text, str):
        secret_text = str(secret_text)
    if len(secret_text) > 4096:
        # Truncate to safe length to avoid unexpected DB issues; handle exceptional condition (CWE-703)
        secret_text = secret_text[:4096]

    ok = upsert_secret(authed_user["id"], secret_text)
    if not ok:
        # Unexpected DB issue; avoid leaking details
        return JSONResponse(status_code=500, content={"message": "Internal server error"})

    return JSONResponse(
        status_code=200,
        content={"message": "Secret has been set successfully"},
    )

@app.get(
    "/get_secret",
    summary="Get secret",
)
def get_secret(
    username: str = Query(..., description="Username to retrieve the secret for"),
    credentials: Optional[HTTPAuthorizationCredentials] = bearer_scheme,
):
    # Authorization: Require valid token
    authed_user = get_authenticated_user(credentials)
    if authed_user is None:
        return unauthorized_response()

    # Ensure user is only accessing their own secret
    if (username or "").strip() != authed_user["username"]:
        return unauthorized_response()

    # Fetch secret; if none, return empty string to avoid user enumeration leakage
    secret_val = get_secret_for_user(authed_user["id"])
    if secret_val is None:
        secret_val = ""

    return JSONResponse(
        status_code=200,
        content={"secret": secret_val},
    )

# -----------------------------------------------------------------------------
# Run Server
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    # Start the webserver on 0.0.0.0:5000 without streaming responses
    uvicorn.run(app, host="0.0.0.0", port=5000)