import os
import sqlite3
import uvicorn
from fastapi import FastAPI, HTTPException, UploadFile, Form, Depends
from fastapi.security import APIKeyHeader
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from typing import Optional
from pathlib import Path
import shutil
import html

app = FastAPI(
    title='Profile Collection',
    description='A simple webapp where anyone can add and view user profiles',
    version='1.0.0'
)

DATABASE = 'db.sqlite3'
PROFILE_PHOTOS_DIR = Path("profile_photos")
SECRET_HEADER_NAME = "APP-SECRET"
APP_SECRET = os.getenv("APP_SECRET")

# Create necessary directories
PROFILE_PHOTOS_DIR.mkdir(exist_ok=True)

# Database initialization
def create_database():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT,
            profile_photo TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Dependency to require API key
def get_secret_header(api_key: str = Depends(APIKeyHeader(name=SECRET_HEADER_NAME))):
    if api_key != APP_SECRET:
        raise HTTPException(status_code=403, detail="Could not validate API key.")

create_database()

# Models
class Profile(BaseModel):
    username: str
    profile_page: str
    profile_photo: Optional[str] = None

@app.post("/add_profile", dependencies=[Depends(get_secret_header)], status_code=201)
async def add_profile(
    username: str = Form(...), 
    profile_page: str = Form(...), 
    profile_photo: UploadFile = Form(...)
):
    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=400, detail="Invalid input, photo must be PNG")
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT 1 FROM profiles WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=403, detail="Profile already exists.")
    
    sanitized_html_content = html.escape(profile_page)
    
    profile_photo_path = PROFILE_PHOTOS_DIR / f"{username}.png"
    with profile_photo_path.open("wb") as buffer:
        shutil.copyfileobj(profile_photo.file, buffer)
    
    cursor.execute('''
        INSERT INTO profiles (username, profile_page, profile_photo)
        VALUES (?, ?, ?)
    ''', (username, sanitized_html_content, str(profile_photo_path)))
    
    conn.commit()
    conn.close()
    return {"message": "Profile created successfully."}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="Profile not found.")
    
    return HTMLResponse(content=row[0], status_code=200)

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="Profile photo not found.")
    
    profile_photo_path = Path(row[0])
    if not profile_photo_path.exists():
        raise HTTPException(status_code=404, detail="Profile photo file not found.")
    
    return FileResponse(profile_photo_path, media_type="image/png")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)