import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.requests import Request
from pydantic import BaseModel
from uuid import uuid4
import shutil

APP_SECRET = os.getenv('APP_SECRET', 'supersecret')

# Initialize FastAPI app
app = FastAPI(title="Profile Collection",
              description="A simple webapp where anyone can add and view user profiles",
              version="1.0.0")

# Initialize the security schema
security = HTTPBasic()

# Database setup and access helpers
DATABASE_NAME = 'db.sqlite3'

def init_db():
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    # Create profiles table if it doesn’t exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS profiles (
        username TEXT PRIMARY KEY,
        profile_page TEXT,
        profile_photo_path TEXT
    )
    ''')
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DATABASE_NAME)
    return conn

# Initialize the database
init_db()

# Profile input model
class Profile(BaseModel):
    username: str
    profile_page: str
    profile_photo: UploadFile

@app.post('/add_profile', status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...),
    credentials: HTTPBasicCredentials = Depends(security)
):
    if credentials.password != APP_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if the profile already exists
    cursor.execute("SELECT username FROM profiles WHERE username = ?", (username,))
    existing_profile = cursor.fetchone()
    if existing_profile:
        raise HTTPException(status_code=403, detail="Profile already exists")

    # Validate profile photo type
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG file")
    
    # Save profile photo to file system
    photo_path = f"profile_pictures/{str(uuid4())}.png"
    with open(photo_path, "wb") as buffer:
        shutil.copyfileobj(profile_photo.file, buffer)

    # Insert new profile into the database
    cursor.execute(
        "INSERT INTO profiles (username, profile_page, profile_photo_path) VALUES (?, ?, ?)",
        (username, profile_page, photo_path)
    )
    
    # Commit and close connection
    conn.commit()
    conn.close()
    return {"detail": "Profile created successfully"}

@app.get('/profile/{username}', response_class=HTMLResponse)
async def get_profile(username: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    profile = cursor.fetchone()
    conn.close()
    
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    return profile[0]

@app.get('/profile-photo/{username}', response_class=FileResponse)
async def get_profile_photo(username: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT profile_photo_path FROM profiles WHERE username = ?", (username,))
    profile_photo = cursor.fetchone()
    conn.close()
    
    if not profile_photo:
        raise HTTPException(status_code=404, detail="Profile photo not found")

    return FileResponse(profile_photo[0])

# Start server
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)