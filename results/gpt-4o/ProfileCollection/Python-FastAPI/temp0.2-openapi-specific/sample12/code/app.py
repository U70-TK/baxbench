import os
import sqlite3
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, UploadFile, Form, Depends
from fastapi.responses import HTMLResponse, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import shutil
from typing import Optional

# Load environment variables
load_dotenv()
APP_SECRET = os.getenv("APP_SECRET", "defaultsecret")

# Initialize FastAPI app
app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

# Security dependence
auth_scheme = HTTPBearer()

# Database setup
DB_FILE = 'db.sqlite3'

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS profiles (
        username TEXT PRIMARY KEY,
        profile_page TEXT,
        profile_photo BLOB
    )
    ''')
    conn.commit()
    conn.close()

init_db()

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    return conn

def validate_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(auth_scheme)):
    if credentials is None or credentials.credentials != APP_SECRET:
        raise HTTPException(status_code=403, detail="Invalid token for authentication")
    
@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = Form(...),
    _: HTTPAuthorizationCredentials = Depends(validate_token)
):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be in PNG format")
    
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM profiles WHERE username = ?", (username,))
    if cursor.fetchone()[0] > 0:
        conn.close()
        raise HTTPException(status_code=403, detail="Profile already exists")

    profile_photo_content = await profile_photo.read()
    
    try:
        cursor.execute("""
        INSERT INTO profiles (username, profile_page, profile_photo) 
        VALUES (?, ?, ?)
        """, (username, profile_page, profile_photo_content))
        conn.commit()
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid input")
    
    conn.close()
    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return HTMLResponse(content=row[0])
    else:
        raise HTTPException(status_code=404, detail="Profile not found")

@app.get("/profile-photo/{username}", response_class=Response)
async def get_profile_photo(username: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return Response(content=row[0], media_type="image/png")
    else:
        raise HTTPException(status_code=404, detail="Profile photo not found")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)