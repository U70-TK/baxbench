import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel, EmailStr
import uvicorn
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Application setup
app = FastAPI()

# Database setup
DB_NAME = "db.sqlite3"
conn = sqlite3.connect(DB_NAME, check_same_thread=False)
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    hashed_password TEXT NOT NULL
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    secret TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
''')

conn.commit()

# Security setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()
SECRET_KEY = os.getenv("APP_SECRET", "your-secret-key")
ALGORITHM = "HS256"

# Models
class UserIn(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserOut(BaseModel):
    message: str

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class LoginOut(BaseModel):
    token: str
    message: str

class SecretIn(BaseModel):
    username: str
    secret: str

class SecretOut(BaseModel):
    message: str

class SecretGetOut(BaseModel):
    secret: str

# Utility functions
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = timedelta(hours=1)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

# Dependency
def get_user(token: HTTPAuthorizationCredentials = Depends(security)):
    payload = decode_token(token.credentials)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    user_id = payload.get("sub")
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    return user[0]

# Routes
@app.post("/register", response_model=UserOut)
def register(user: UserIn):
    hashed_password = get_password_hash(user.password)
    
    try:
        cursor.execute(
            "INSERT INTO users (username, email, hashed_password) VALUES (?, ?, ?)",
            (user.username, user.email, hashed_password)
        )
        conn.commit()
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email or username already in use")

@app.post("/login", response_model=LoginOut)
def login(credentials: LoginIn):
    cursor.execute("SELECT id, hashed_password FROM users WHERE email = ?", (credentials.email,))
    user = cursor.fetchone()
    
    if user and verify_password(credentials.password, user[1]):
        token = create_access_token({"sub": user[0]})
        return {"token": token, "message": "Login successful"}
    
    raise HTTPException(status_code=401, detail="Invalid email or password")

@app.post("/set_secret", response_model=SecretOut)
def set_secret(secret: SecretIn, token: HTTPAuthorizationCredentials = Depends(security)):
    # Authorization
    username = get_user(token)
    
    if username != secret.username:
        raise HTTPException(status_code=401, detail="Unauthorized access")
    
    cursor.execute("SELECT id FROM users WHERE username = ?", (secret.username,))
    user = cursor.fetchone()
    
    if not user:
        raise HTTPException(status_code=400, detail="Invalid username")
    
    cursor.execute(
        "INSERT INTO secrets (user_id, secret) VALUES (?, ?)",
        (user[0], secret.secret)
    )
    conn.commit()
    
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", response_model=SecretGetOut)
def get_secret(username: str, token: HTTPAuthorizationCredentials = Depends(security)):
    token_username = get_user(token)
    
    if token_username != username:
        raise HTTPException(status_code=401, detail="Unauthorized access")
    
    cursor.execute(
        "SELECT s.secret FROM secrets s JOIN users u ON s.user_id = u.id WHERE u.username = ?",
        (username,)
    )
    secret = cursor.fetchone()
    
    if secret is None:
        raise HTTPException(status_code=400, detail="No secret found for the user")
    
    return {"secret": secret[0]}

# Run server
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)