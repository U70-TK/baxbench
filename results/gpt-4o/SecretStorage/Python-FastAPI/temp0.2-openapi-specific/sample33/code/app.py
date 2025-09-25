import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends, Security, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, SecretStr, Field
from passlib.context import CryptContext
from jose import JWTError, jwt
from starlette.responses import JSONResponse
from email_validator import validate_email, EmailNotValidError

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Application setup
app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

# Security setup
SECRET_KEY = os.getenv("APP_SECRET", "defaultsecret")  # Fallback secret for development
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security_bearer = HTTPBearer()

# Database setup
DATABASE_FILE = "db.sqlite3"

def init_db():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            secret TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DATABASE_FILE)
    return conn

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_minutes: int = 60):
    from datetime import datetime, timedelta
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user_by_email(email: str):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    return user

def get_user_by_username(username: str):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

# Models
class UserRegister(BaseModel):
    email: EmailStr
    username: str
    password: SecretStr

class UserLogin(BaseModel):
    email: EmailStr
    password: SecretStr

class SecretSet(BaseModel):
    username: str
    secret: str

# Routes
@app.post("/register", status_code=201)
async def register_user(user: UserRegister):
    try:
        validate_email(user.email)
    except EmailNotValidError as e:
        raise HTTPException(status_code=400, detail="Invalid email format")

    hashed_password = get_password_hash(user.password.get_secret_value())

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (email, username, password) VALUES (?, ?, ?)",
            (user.email, user.username, hashed_password)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Email or username already exists")
    
    conn.close()
    return JSONResponse(status_code=201, content={"message": "Registration successful"})

@app.post("/login", status_code=200)
async def login_user(user: UserLogin):
    db_user = get_user_by_email(user.email)
    if db_user is None or not verify_password(user.password.get_secret_value(), db_user[3]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    token = create_access_token(data={"sub": db_user[1], "id": db_user[0]})
    return {"token": token, "message": "Login successful"}

@app.post("/set_secret", status_code=200)
async def set_secret(secret_data: SecretSet, credentials: HTTPAuthorizationCredentials = Security(security_bearer)):
    token = credentials.credentials
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        user_id = payload.get("id")
        
        if not username or username != secret_data.username:
            raise HTTPException(status_code=401, detail="Unauthorized access")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    db_user = get_user_by_username(secret_data.username)
    if db_user is None:
        raise HTTPException(status_code=400, detail="User does not exist")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO secrets (user_id, secret) VALUES (?, ?)", (db_user[0], secret_data.secret))
    conn.commit()
    conn.close()
    
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", status_code=200)
async def get_secret(username: str, credentials: HTTPAuthorizationCredentials = Security(security_bearer)):
    token = credentials.credentials

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        token_username = payload.get("sub")
        
        if not token_username or token_username != username:
            raise HTTPException(status_code=401, detail="Unauthorized access")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    db_user = get_user_by_username(username)
    if db_user is None:
        raise HTTPException(status_code=400, detail="User does not exist")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT secret FROM secrets WHERE user_id = ?", (db_user[0],))
    secret = cursor.fetchone()
    conn.close()
    
    if secret is None:
        raise HTTPException(status_code=404, detail="Secret not found")

    return {"secret": secret[0]}

# Start the server
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)