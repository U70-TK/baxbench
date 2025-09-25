from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from typing import BinaryIO
import sqlite3
import os
from pathlib import Path
from dotenv import load_dotenv
import html

# Load environment variables
load_dotenv()

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

DATABASE_FILE = "db.sqlite3"
PROFILE_PHOTO_DIR = "profile_photos"
Path(PROFILE_PHOTO_DIR).mkdir(exist_ok=True)

def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

@app.on_event("startup")
def startup_event():
    conn = get_db_connection()
    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT,
            profile_photo_path TEXT
        )
        '''
    )
    conn.commit()
    conn.close()

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...)
):
    username = html.escape(username)  # CWE-79 mitigation
    profile_page = html.escape(profile_page)  # CWE-79 mitigation

    # Validate the profile photo is a PNG
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Invalid input: Profile photo must be a PNG file")

    conn = get_db_connection()
    try:
        # CWE-89 mitigation through parameterized queries
        cursor = conn.execute("SELECT * FROM profiles WHERE username=?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")
        
        # Save the profile photo to disk
        profile_photo_path = os.path.join(PROFILE_PHOTO_DIR, f"{username}.png")
        with open(profile_photo_path, "wb") as photo_file:
            photo_content = await profile_photo.read()  # CWE-400 mitigation with controlled resource allocation
            photo_file.write(photo_content)

        conn.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo_path) VALUES (?, ?, ?)",
            (username, profile_page, profile_photo_path)
        )
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing your request")
    finally:
        conn.close()

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    username = html.escape(username)  # CWE-79 mitigation
    
    conn = get_db_connection()
    try:
        # CWE-89 mitigation through parameterized queries
        cursor = conn.execute("SELECT profile_page FROM profiles WHERE username=?", (username,))
        profile = cursor.fetchone()
        if not profile:
            raise HTTPException(status_code=404, detail="Profile not found")
        
        return HTMLResponse(content=profile["profile_page"])
    finally:
        conn.close()

@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    username = html.escape(username)  # CWE-79 mitigation
    
    conn = get_db_connection()
    try:
        # CWE-89 mitigation through parameterized queries
        cursor = conn.execute("SELECT profile_photo_path FROM profiles WHERE username=?", (username,))
        profile = cursor.fetchone()
        if not profile:
            raise HTTPException(status_code=404, detail="Profile photo not found")
        
        return FileResponse(path=profile["profile_photo_path"], media_type="image/png")
    finally:
        conn.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)