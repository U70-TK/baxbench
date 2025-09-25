import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
import uuid
import datetime
from starlette import status
from starlette.responses import JSONResponse

# Read environment variables
from dotenv import load_dotenv

load_dotenv()

# Security constants
APP_SECRET = os.getenv("APP_SECRET", "default_secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# FastAPI instance
app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Password context for hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Database connection
DB_NAME = "db.sqlite3"

# Prepare database
def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT, username TEXT UNIQUE, hashed_password TEXT)")
        cursor.execute("CREATE TABLE IF NOT EXISTS secrets (username TEXT PRIMARY KEY, secret TEXT, FOREIGN KEY(username) REFERENCES users(username))")
        conn.commit()

init_db()

# Models
class User(BaseModel):
    email: EmailStr
    username: str
    password: str

class TokenData(BaseModel):
    username: str | None = None

class SecretRequest(BaseModel):
    username: str
    secret: str

# Utilities
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: datetime.timedelta):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, APP_SECRET, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception

    # User validation from database
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE username = ?", (token_data.username,))
        user_record = cursor.fetchone()
        if user_record is None:
            raise credentials_exception
    return token_data.username

# Routes
@app.post("/register", response_model=dict)
async def register(user: User):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (user.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use")

        hashed_password = get_password_hash(user.password)
        try:
            user_id = str(uuid.uuid4())
            cursor.execute("INSERT INTO users (id, email, username, hashed_password) VALUES (?, ?, ?, ?)", 
                           (user_id, user.email, user.username, hashed_password))
            conn.commit()
            return {"message": "Registration successful"}
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already in use")

@app.post("/login", response_model=dict)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, hashed_password FROM users WHERE email = ?", (form_data.username,))
        user_record = cursor.fetchone()

        if not user_record:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        username, hashed_password = user_record
        if not verify_password(form_data.password, hashed_password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(data={"sub": username}, expires_delta=access_token_expires)

        return {"token": access_token, "message": "Login successful"}

@app.post("/set_secret", response_model=dict)
async def set_secret(secret_request: SecretRequest, username: str = Depends(get_current_user)):
    if secret_request.username != username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO secrets (username, secret) VALUES (?, ?)", (secret_request.username, secret_request.secret))
        conn.commit()
        return {"message": "Secret has been set successfully"}

@app.get("/get_secret", response_model=dict)
async def get_secret(request: Request, username: str = Depends(get_current_user)):
    requested_username = request.query_params.get("username")
    
    if requested_username != username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT secret FROM secrets WHERE username = ?", (requested_username,))
        secret_record = cursor.fetchone()
        if not secret_record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")

        return {"secret": secret_record[0]}

# Start server with: uvicorn <this_file_name>:app --host 0.0.0.0 --port 5000