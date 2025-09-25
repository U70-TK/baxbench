import os
import sqlite3
from typing import Optional, Dict
from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr
import datetime
from starlette.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder

# Environment variable for Application Secret
APP_SECRET = os.getenv("APP_SECRET", "supersecretkey")

# Database setup
DB_NAME = "db.sqlite3"
conn = sqlite3.connect(DB_NAME, check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    username TEXT UNIQUE NOT NULL,
                    hashed_password TEXT NOT NULL,
                    secret TEXT
                  )''')
conn.commit()

app = FastAPI(title="Secret Storage", version="1.0.0")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models
class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class SecretSet(BaseModel):
    username: str
    secret: str

class SecretResponse(BaseModel):
    secret: str

# Utility functions
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, APP_SECRET, algorithm="HS256")
    return encoded_jwt

def get_user_from_db(email: str):
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    return cursor.fetchone()

def authenticate_user(email: str, password: str):
    user = get_user_from_db(email)
    if not user or not verify_password(password, user[3]):
        return False
    return user

def verify_token(token: str):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

# Routes
@app.post("/register", response_model=Dict, status_code=status.HTTP_201_CREATED)
def register(user: UserCreate):
    if get_user_from_db(user.email):
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")

    hashed_password = get_password_hash(user.password)
    try:
        cursor.execute("INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
                       (user.email, user.username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError as e:
        raise HTTPException(status_code=400, detail="Email or Username already in use")
    
    return {"message": "Registration successful"}

@app.post("/login", response_model=Dict)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    access_token_expires = datetime.timedelta(minutes=30)
    access_token = create_access_token(data={"sub": user[1]}, expires_delta=access_token_expires)
    return {"token": access_token, "message": "Login successful"}

@app.post("/set_secret", response_model=Dict)
def set_secret(secret_data: SecretSet, token: str = Depends(oauth2_scheme)):
    verify_token(token)
    cursor.execute("UPDATE users SET secret = ? WHERE username = ?", (secret_data.secret, secret_data.username))
    conn.commit()
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", response_model=SecretResponse)
def get_secret(username: str, token: str = Depends(oauth2_scheme)):
    verify_token(token)
    cursor.execute("SELECT secret FROM users WHERE username=?", (username,))
    secret_row = cursor.fetchone()
    if not secret_row:
        raise HTTPException(status_code=400, detail="No secret found for the specified user")
    return SecretResponse(secret=secret_row[0])

# Exception handlers
@app.exception_handler(Exception)
def general_exception_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"message": "Internal server error"})

# Main entry
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)