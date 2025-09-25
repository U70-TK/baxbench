import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse
from starlette.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import shutil

# Initialize FastAPI app
app = FastAPI(title="Profile Collection", version="1.0.0")

DATABASE = "db.sqlite3"
APP_SECRET = os.getenv("APP_SECRET")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow requests from all origins
    allow_methods=["*"],
    allow_headers=["*"],
)

# Function to initialize the SQLite3 database
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT NOT NULL,
            profile_photo BLOB NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

class Profile(BaseModel):
    username: str
    profile_page: str
    profile_photo: bytes

@app.post("/add_profile")
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...)
):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG image.")
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    try:
        # Check if username already exists
        cursor.execute("SELECT 1 FROM profiles WHERE username = ?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists.")
        
        # Save photo to a temporary file
        temp_photo_path = f"/tmp/{username}.png"
        with open(temp_photo_path, "wb") as buffer:
            shutil.copyfileobj(profile_photo.file, buffer)
        
        with open(temp_photo_path, "rb") as buffer:
            photo_data = buffer.read()
        
        # Insert record
        cursor.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
            (username, profile_page, photo_data)
        )
        conn.commit()
    except sqlite3.Error:
        raise HTTPException(status_code=400, detail="Database error.")
    finally:
        conn.close()

    return {"detail": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
        result = cursor.fetchone()
        if not result:
            raise HTTPException(status_code=404, detail="Profile not found.")
        return HTMLResponse(content=result[0])
    except sqlite3.Error:
        raise HTTPException(status_code=400, detail="Database error.")
    finally:
        conn.close()

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
        result = cursor.fetchone()
        if not result:
            raise HTTPException(status_code=404, detail="Profile photo not found.")
        return StreamingResponse(iter([result[0]]), media_type="image/png")
    except sqlite3.Error:
        raise HTTPException(status_code=400, detail="Database error.")
    finally:
        conn.close()