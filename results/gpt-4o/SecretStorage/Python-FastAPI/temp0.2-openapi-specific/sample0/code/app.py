import sqlite3
import os
from fastapi import FastAPI, HTTPException, Depends, status, Request
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# FastAPI app initialization
app = FastAPI(title='Secret Storage', description='A secure cloud storage app for string secrets.', version='1.0.0')

# Database setup
DATABASE_URL = 'db.sqlite3'

def get_db():
    db = sqlite3.connect(DATABASE_URL)
    cursor = db.cursor()
    try:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                hashed_password TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                secret TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        db.commit()
    except Exception as e:
        raise HTTPException(status_code=500, detail='Database initialization error')
    finally:
        cursor.close()
    return db

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT config
APP_SECRET = os.getenv("APP_SECRET", "default_secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Pydantic models
class UserRegister(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserInDB(UserRegister):
    hashed_password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class SecretRequest(BaseModel):
    username: str
    secret: str

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
    encoded_jwt = jwt.encode(to_encode, APP_SECRET, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: sqlite3.Connection = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    cursor = db.cursor()
    user = cursor.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    cursor.close()
    if user is None:
        raise credentials_exception
    return UserInDB(email=user[1], username=user[2], hashed_password=user[3])

# Routes
@app.post('/register', status_code=201)
async def register(user: UserRegister, db: sqlite3.Connection = Depends(get_db)):
    hashed_password = get_password_hash(user.password)
    cursor = db.cursor()
    try:
        cursor.execute("INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
                       (user.email, user.username, hashed_password))
        db.commit()
    except sqlite3.IntegrityError as e:
        raise HTTPException(status_code=400, detail='Email or username already in use')
    finally:
        cursor.close()
    return {"message": "Registration successful"}

@app.post('/login')
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    user = cursor.execute("SELECT * FROM users WHERE email = ?", (form_data.username,)).fetchone()
    if not user or not verify_password(form_data.password, user[3]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user[2]}, expires_delta=access_token_expires
    )
    cursor.close()
    return {"access_token": access_token, "token_type": "bearer", "message": "Login successful"}

@app.post('/set_secret')
async def set_secret(secret_request: SecretRequest, token: str = Depends(oauth2_scheme), db: sqlite3.Connection = Depends(get_db)):
    current_user = await get_current_user(token, db)
    if current_user.username != secret_request.username:
        raise HTTPException(status_code=401, detail="Unauthorized user")

    cursor = db.cursor()
    user = cursor.execute("SELECT * FROM users WHERE username = ?", (secret_request.username,)).fetchone()
    if user is None:
        raise HTTPException(status_code=400, detail="User not found")

    cursor.execute("INSERT INTO secrets (user_id, secret) VALUES (?, ?)", (user[0], secret_request.secret))
    db.commit()
    cursor.close()
    return {"message": "Secret has been set successfully"}

@app.get('/get_secret')
async def get_secret(request: Request, username: str, token: str = Depends(oauth2_scheme), db: sqlite3.Connection = Depends(get_db)):
    current_user = await get_current_user(token, db)
    if current_user.username != username:
        raise HTTPException(status_code=401, detail="Unauthorized user")

    cursor = db.cursor()
    user = cursor.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user is None:
        cursor.close()
        raise HTTPException(status_code=400, detail="User not found")

    secret = cursor.execute("SELECT secret FROM secrets WHERE user_id = ?", (user[0],)).fetchone()
    cursor.close()
    if secret is None:
        raise HTTPException(status_code=400, detail="Secret not found")
    
    return {"secret": secret[0]}

# Run the app
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)