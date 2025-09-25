import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends, status, Body
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, constr
from datetime import datetime, timedelta

# Configuration
DATABASE = "db.sqlite3"
SECRET_KEY = os.getenv("APP_SECRET", "your-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# FastAPI app instance
app = FastAPI(title="Secret Storage", version="1.0.0", description="A secure cloud storage app for string secrets.")

# Database setup
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                email TEXT UNIQUE,
                username TEXT UNIQUE,
                hashed_password TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                secret TEXT
            )
        ''')
        conn.commit()

init_db()

# Password context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Models and Schemas
class UserIn(BaseModel):
    email: EmailStr
    username: str
    password: constr(min_length=6)

class UserInDB(UserIn):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Utility Functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(email: str):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        row = cursor.fetchone()
    return UserInDB(**dict(zip([column[0] for column in cursor.description], row))) if row else None

def authenticate_user(email: str, password: str):
    user = get_user(email)
    if user and verify_password(password, user.hashed_password):
        return user
    return None

# Endpoints
@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user: UserIn):
    hashed_password = get_password_hash(user.password)
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (email, username, hashed_password) VALUES (?, ?, ?)",
                           (user.email, user.username, hashed_password))
            conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email or username already in use")

    return {"message": "Registration successful"}

@app.post("/login", response_model=Token)
async def login(email: str = Body(...), password: str = Body(...)):
    user = authenticate_user(email, password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token}

@app.post("/set_secret")
async def set_secret(username: str = Body(...), secret: str = Body(...), token: str = Depends(oauth2_scheme)):
    email = None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    if not email or get_user(email).username != username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO secrets (username, secret) VALUES (?, ?)", (username, secret))
        conn.commit()
    
    return {"message": "Secret has been set successfully"}

@app.get("/get_secret")
async def get_secret(username: str, token: str = Depends(oauth2_scheme)):
    email = None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    if not email or get_user(email).username != username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT secret FROM secrets WHERE username=?", (username,))
        row = cursor.fetchone()

    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")

    return {"secret": row[0]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)