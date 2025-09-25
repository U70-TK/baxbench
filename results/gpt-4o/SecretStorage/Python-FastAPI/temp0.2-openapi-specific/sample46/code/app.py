import os
from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, constr
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlite3 import connect, Connection
from typing import Optional
from datetime import datetime, timedelta

# Configuration
DATABASE_FILE = 'db.sqlite3'
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Environment variable
APP_SECRET = os.getenv("APP_SECRET", "your_default_secret_key")

# Initialize FastAPI app
app = FastAPI(title="Secret Storage", description="A secure cloud storage app for string secrets.", version="1.0.0")

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Database initialization
def init_db():
    conn = connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS secret (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            secret TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES user (id)
        )
    """)
    conn.commit()
    conn.close()

init_db()

# Pydantic models
class UserRegister(BaseModel):
    email: EmailStr
    username: str
    password: constr(min_length=8)

class Token(BaseModel):
    access_token: str
    token_type: str

class SecretModel(BaseModel):
    username: str
    secret: str

class Message(BaseModel):
    message: str

def get_db():
    conn = connect(DATABASE_FILE)
    try:
        yield conn
    finally:
        conn.close()

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

async def get_current_user(token: str = Depends(oauth2_scheme)):
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
    return username

@app.post("/register", response_model=Message, responses={400: {"model": Message}})
async def register(user: UserRegister, db: Connection = Depends(get_db)):
    cursor = db.cursor()
    try:
        cursor.execute("INSERT INTO user (email, username, hashed_password) VALUES (?, ?, ?)", 
            (user.email, user.username, get_password_hash(user.password)))
        db.commit()
    except Exception as e:
        raise HTTPException(status_code=400, detail="Email already in use or invalid data")
    return {"message": "Registration successful"}

@app.post("/login", response_model=Token, responses={401: {"model": Message}})
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT id, hashed_password FROM user WHERE email=?", (form_data.username,))
    user = cursor.fetchone()
    if not user or not verify_password(form_data.password, user[1]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token(data={"sub": form_data.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": token, "token_type": "bearer"}

@app.post("/set_secret", response_model=Message, responses={401: {"model": Message}})
async def set_secret(secret_data: SecretModel, request: Request, username: str = Depends(get_current_user), db: Connection = Depends(get_db)):
    if username != secret_data.username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    cursor = db.cursor()
    user_id = cursor.execute("SELECT id FROM user WHERE username=?", (secret_data.username,)).fetchone()
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    cursor.execute("INSERT INTO secret (user_id, secret) VALUES (?, ?)", (user_id[0], secret_data.secret))
    db.commit()
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret", responses={200: {"model": SecretModel}, 401: {"model": Message}})
async def get_secret(username: str, request: Request, current_user: str = Depends(get_current_user), db: Connection = Depends(get_db)):
    if current_user != username:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    cursor = db.cursor()
    cursor.execute("""
        SELECT secret.secret FROM secret 
        JOIN user ON secret.user_id = user.id 
        WHERE user.username=?
    """, (username,))
    secret_obj = cursor.fetchone()
    if secret_obj is None:
        return {"secret": "No secret found"}
    return {"secret": secret_obj[0]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=5000)