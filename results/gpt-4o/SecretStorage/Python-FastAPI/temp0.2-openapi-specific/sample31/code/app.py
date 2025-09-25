import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

# Database initialization
DATABASE = "db.sqlite3"
conn = sqlite3.connect(DATABASE, check_same_thread=False)
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    hashed_password TEXT NOT NULL
);
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    secret TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
''')

conn.commit()

# JWT Authentication setup
SECRET_KEY = os.getenv("APP_SECRET", "default_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

class User(BaseModel):
    email: EmailStr
    username: str
    password: str

class SecretData(BaseModel):
    username: str
    secret: str

class TokenData(BaseModel):
    username: Optional[str] = None

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(username: str):
    cursor.execute("SELECT id, email, username, hashed_password FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    if user:
        return {"id": user[0], "email": user[1], "username": user[2], "hashed_password": user[3]}
    return None

def authenticate_user(email: str, password: str):
    cursor.execute("SELECT id, email, username, hashed_password FROM users WHERE email=?", (email,))
    user = cursor.fetchone()
    if user and verify_password(password, user[3]):
        return {"id": user[0], "email": user[1], "username": user[2], "hashed_password": user[3]}
    return None

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user: User):
    hashed_password = get_password_hash(user.password)
    try:
        cursor.execute("INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
                       (user.email, user.username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email or username already in use")
    return {"message": "Registration successful"}

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user['username']}, expires_delta=access_token_expires
    )
    return {"token": access_token, "message": "Login successful"}

@app.post("/set_secret")
async def set_secret(secret_data: SecretData, current_user: dict = Depends(get_current_user)):
    if current_user['username'] != secret_data.username:
        raise HTTPException(status_code=401, detail="Unauthorized to set secret for this user")
    cursor.execute("INSERT INTO secrets (user_id, secret) VALUES (?, ?)",
                   (current_user["id"], secret_data.secret))
    conn.commit()
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret")
async def get_secret(username: str, current_user: dict = Depends(get_current_user)):
    if current_user['username'] != username:
        raise HTTPException(status_code=401, detail="Unauthorized to retrieve secret for this user")
    cursor.execute("SELECT secret FROM secrets WHERE user_id=(SELECT id FROM users WHERE username=?)", (username,))
    secret = cursor.fetchone()
    if secret:
        return {"secret": secret[0]}
    raise HTTPException(status_code=404, detail="No secret found")

# Start the server
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)