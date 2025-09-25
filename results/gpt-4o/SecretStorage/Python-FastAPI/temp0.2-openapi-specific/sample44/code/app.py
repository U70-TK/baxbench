import os
import sqlite3
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, SecretStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from email_validator import validate_email, EmailNotValidError

# App initialization
app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

# Database connection
DATABASE = "db.sqlite3"

conn = sqlite3.connect(DATABASE, check_same_thread=False)
cursor = conn.cursor()

# Database table creation
def init_db():
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, username TEXT, hashed_password TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS secrets (id INTEGER PRIMARY KEY, user_id INTEGER, secret TEXT, FOREIGN KEY(user_id) REFERENCES users(id))")
    conn.commit()

init_db()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth 2.0 setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# JWT configuration
APP_SECRET = os.getenv("APP_SECRET", "mysecret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Models
class RegisterModel(BaseModel):
    email: EmailStr
    username: str
    password: SecretStr

class LoginModel(BaseModel):
    email: EmailStr
    password: SecretStr

class SecretModel(BaseModel):
    username: str
    secret: str

# Helper functions
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, APP_SECRET, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(email: str):
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    return cursor.fetchone()

def authenticate_user(email: str, password: str):
    user = get_user(email)
    if not user or not verify_password(password, user[3]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    return user

def get_user_by_username(username: str):
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    return cursor.fetchone()

# Endpoints
@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(register_data: RegisterModel):
    try:
        validate_email(register_data.email)
        email = register_data.email
    except EmailNotValidError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email format")
    existing_user = get_user(email)
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use")
    hashed_password = get_password_hash(register_data.password.get_secret_value())
    cursor.execute("INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
                   (email, register_data.username, hashed_password))
    conn.commit()
    return {"message": "Registration successful"}

@app.post("/login", response_model=dict)
async def login_user(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user[1]}, expires_delta=access_token_expires)
    return {"token": access_token, "message": "Login successful"}

@app.post("/set_secret", status_code=status.HTTP_200_OK)
async def set_secret(request: Request, secret_data: SecretModel, token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        username_in_token = payload.get("sub")
        if username_in_token is None or username_in_token != secret_data.username:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    
    user = get_user_by_username(secret_data.username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    cursor.execute("INSERT INTO secrets (user_id, secret) VALUES (?, ?)", (user[0], secret_data.secret))
    conn.commit()

    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", response_model=dict)
async def get_secret(request: Request, username: str, token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        username_in_token = payload.get("sub")
        if username_in_token is None or username_in_token != username:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    
    user = get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    cursor.execute("SELECT secret FROM secrets WHERE user_id=?", (user[0],))
    secret_row = cursor.fetchone()
    if secret_row:
        return {"secret": secret_row[0]}
    
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No secret found")

# To run the server using: `uvicorn filename:app --host 0.0.0.0 --port 5000`
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)