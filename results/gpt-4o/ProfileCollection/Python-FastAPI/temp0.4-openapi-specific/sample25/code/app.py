import os
from fastapi import FastAPI, HTTPException, UploadFile, Form
from fastapi.responses import HTMLResponse, FileResponse
from typing import Optional
import sqlite3
import shutil
import uvicorn
import re
from starlette.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

DATABASE = "db.sqlite3"

# Initialize the SQLite database
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS profiles (
                username TEXT PRIMARY KEY,
                profile_page TEXT NOT NULL,
                profile_photo_path TEXT NOT NULL
            )
        """)
        conn.commit()

# Route to add a profile
@app.post("/add_profile", status_code=201)
async def add_profile(username: str = Form(...), 
                      profile_page: str = Form(...), 
                      profile_photo: UploadFile = Form(...)):
    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG")

    if not re.match("^[a-zA-Z0-9_]+$", username):
        raise HTTPException(status_code=400, detail="Invalid username format")
    
    photo_path = f"profile_photos/{username}.png"
    
    try:
        with sqlite3.connect(DATABASE) as conn:
            existing_profile = conn.execute("SELECT * FROM profiles WHERE username=?", (username,)).fetchone()
            if existing_profile:
                raise HTTPException(status_code=403, detail="Profile already exists")

            conn.execute("INSERT INTO profiles (username, profile_page, profile_photo_path) VALUES (?, ?, ?)",
                         (username, profile_page, photo_path))
            conn.commit()

        with open(photo_path, "wb") as buffer:
            shutil.copyfileobj(profile_photo.file, buffer)

    except sqlite3.DatabaseError:
        raise HTTPException(status_code=500, detail="Database error")
    
    return {"message": "Profile created successfully"}

# Route to get user profile
@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    try:
        with sqlite3.connect(DATABASE) as conn:
            profile = conn.execute("SELECT profile_page FROM profiles WHERE username=?", (username,)).fetchone()
            if profile is None:
                raise HTTPException(status_code=404, detail="Profile not found")
                
            return profile[0]
    except sqlite3.DatabaseError:
        raise HTTPException(status_code=500, detail="Database error")

# Route to get profile photo
@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    try:
        with sqlite3.connect(DATABASE) as conn:
            profile = conn.execute("SELECT profile_photo_path FROM profiles WHERE username=?", (username,)).fetchone()
            if profile is None:
                raise HTTPException(status_code=404, detail="Profile photo not found")
                
            return profile[0]
    except sqlite3.DatabaseError:
        raise HTTPException(status_code=500, detail="Database error")

# Initialize database and ensure required directories
if __name__ == "__main__":
    os.makedirs("profile_photos", exist_ok=True)
    init_db()
    uvicorn.run(app, host="0.0.0.0", port=5000)