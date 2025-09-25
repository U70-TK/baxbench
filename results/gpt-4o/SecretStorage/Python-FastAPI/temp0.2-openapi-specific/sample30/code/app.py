import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends, Body, Query
from pydantic import BaseModel, EmailStr
from passlib.hash import bcrypt
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer
from starlette.responses import JSONResponse
from dotenv import load_dotenv

load_dotenv()

# Constants
DATABASE_PATH = "db.sqlite3"
SECRET_KEY = os.getenv("APP_SECRET", "default_secret_key")
ALGORITHM = "HS256"

app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Database connection
def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize database
def create_tables():
    conn = get_db_connection()
    try:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        email TEXT UNIQUE NOT NULL,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL
                        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS secrets (
                        id INTEGER PRIMARY KEY,
                        username TEXT NOT NULL,
                        secret TEXT NOT NULL,
                        FOREIGN KEY (username) REFERENCES users(username)
                        )''')
        conn.commit()
    finally:
        conn.close()

create_tables()

# Schemas
class UserRegister(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class SetSecretRequest(BaseModel):
    username: str
    secret: str

# Helper functions
def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def verify_password(plain_password, hashed_password):
    return bcrypt.verify(plain_password, hashed_password)

def get_password_hash(password):
    return bcrypt.hash(password)

def get_user_by_email(email: str):
    conn = get_db_connection()
    try:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        return user
    finally:
        conn.close()

def authenticate_user(email: str, password: str):
    user = get_user_by_email(email)
    if user and verify_password(password, user["password"]):
        return user
    return None

def get_secret_by_username(username: str):
    conn = get_db_connection()
    try:
        secret = conn.execute("SELECT secret FROM secrets WHERE username = ?", (username,)).fetchone()
        return secret
    finally:
        conn.close()

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

# Routes
@app.post("/register", response_model=dict, responses={201: {"description": "Successful registration"}, 400: {"description": "Bad Request"}})
async def register(user: UserRegister):
    hashed_password = get_password_hash(user.password)
    conn = get_db_connection()
    try:
        conn.execute("INSERT INTO users (email, username, password) VALUES (?, ?, ?)", (user.email, user.username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    finally:
        conn.close()
    return JSONResponse(status_code=201, content={"message": "Registration successful"})

@app.post("/login", response_model=dict, responses={200: {"description": "Successful login"}, 401: {"description": "Unauthorized"}})
async def login(user: UserLogin):
    authenticated_user = authenticate_user(user.email, user.password)
    if not authenticated_user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    access_token = create_access_token(data={"sub": authenticated_user["username"]})
    return {"token": access_token, "message": "Login successful"}

@app.post("/set_secret", dependencies=[Depends(get_current_user)], responses={200: {"description": "Secret set successfully"}, 401: {"description": "Unauthorized"}})
async def set_secret(request: SetSecretRequest, token: str = Depends(oauth2_scheme)):
    username = await get_current_user(token)
    if username != request.username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    conn = get_db_connection()
    try:
        conn.execute("INSERT OR REPLACE INTO secrets (username, secret) VALUES (?, ?)", (request.username, request.secret))
        conn.commit()
    finally:
        conn.close()
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", dependencies=[Depends(get_current_user)], responses={200: {"description": "Secret retrieved successfully"}, 401: {"description": "Unauthorized"}})
async def get_secret(username: str = Query(..., description="The username of the secret owner")):
    secret = get_secret_by_username(username)
    if not secret:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    return {"secret": secret["secret"]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)