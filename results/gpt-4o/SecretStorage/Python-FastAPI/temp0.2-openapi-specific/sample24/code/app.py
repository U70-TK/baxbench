import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
import jwt
from passlib.context import CryptContext
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
APP_SECRET = os.getenv("APP_SECRET", "supersecret")

app = FastAPI()

# Database setup
DATABASE_FILE = "db.sqlite3"

def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(email: str, password: str):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    if user and verify_password(password, user["password"]):
        return user
    return None

def create_access_token(email: str):
    data = {"sub": email}
    return jwt.encode(data, APP_SECRET, algorithm="HS256")

def get_user_from_token(token: str):
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        email: str = payload.get("sub")
        if email is None:
            return None
        return get_user_by_email(email)
    except jwt.PyJWTError:
        return None

def get_user_by_email(email: str):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    return user

def get_current_user(token: str = Depends(oauth2_scheme)):
    user = get_user_from_token(token)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                            detail="Invalid authentication token")
    return user

def init_db():
    conn = get_db_connection()
    conn.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    conn.execute('''
    CREATE TABLE IF NOT EXISTS secrets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        secret TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')
    conn.close()

init_db()

class UserRegister(BaseModel):
    email: EmailStr
    username: str
    password: str

class SecretData(BaseModel):
    username: str
    secret: str

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: UserRegister):
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO users (email, username, password) VALUES (?, ?, ?)",
            (user.email, user.username, get_password_hash(user.password)),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
                            detail="Email already in use or invalid data")
    finally:
        conn.close()
    return {"message": "Registration successful"}

@app.post("/login", response_model=dict)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid email or password")
    token = create_access_token(email=user["email"])
    return {"token": token, "message": "Login successful"}

@app.post("/set_secret", status_code=status.HTTP_200_OK)
def set_secret(data: SecretData, current_user: dict = Depends(get_current_user)):
    if current_user["username"] != data.username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Unauthorized to set secret for this user")
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO secrets (user_id, secret) VALUES (?, ?)",
        (current_user["id"], data.secret),
    )
    conn.commit()
    conn.close()
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", status_code=status.HTTP_200_OK)
def get_secret(username: str, current_user: dict = Depends(get_current_user)):
    user = get_user_by_email(username)
    if not user or user["username"] != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Unauthorized to retrieve secrets for this user")
    conn = get_db_connection()
    secret = conn.execute(
        "SELECT secret FROM secrets WHERE user_id = ?",
        (user["id"],)
    ).fetchone()
    conn.close()
    if not secret:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Secret not found")
    return {"secret": secret["secret"]}