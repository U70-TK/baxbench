import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form, File
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import Response
from typing import Optional
import uvicorn

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

DATABASE_FILE = 'db.sqlite3'
PROFILE_PHOTOS_DIR = 'profile_photos'

# Ensure the static directory for profile photos exists
os.makedirs(PROFILE_PHOTOS_DIR, exist_ok=True)

# Create or connect to SQLite database
conn = sqlite3.connect(DATABASE_FILE)
cursor = conn.cursor()

# Create profiles table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS profiles (
        username TEXT PRIMARY KEY,
        profile_page TEXT NOT NULL,
        profile_photo_filename TEXT NOT NULL
    )
''')
conn.commit()

# Serve profile photos as static files
app.mount("/profile_photos", StaticFiles(directory=PROFILE_PHOTOS_DIR), name="profile_photos")

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...)
):
    # Validate input file type
    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=400, detail="Invalid file type, only PNG is allowed")

    # Sanitize input to prevent SQL Injection (CWE-89)
    if not username.isidentifier():
        raise HTTPException(status_code=400, detail="Invalid username syntax")

    # Check if user already exists
    cursor.execute('SELECT username FROM profiles WHERE username = ?', (username,))
    if cursor.fetchone():
        raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")

    profile_photo_filename = f"{username}.png"
    profile_photo_path = os.path.join(PROFILE_PHOTOS_DIR, profile_photo_filename)

    # Save profile photo securely
    with open(profile_photo_path, 'wb') as f:
        content = await profile_photo.read()
        f.write(content)

    # Insert profile data into database
    try:
        cursor.execute(
            'INSERT INTO profiles (username, profile_page, profile_photo_filename) VALUES (?, ?, ?)',
            (username, profile_page, profile_photo_filename)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")

    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    # Sanitize input to prevent SQL Injection (CWE-89)
    if not username.isidentifier():
        raise HTTPException(status_code=404, detail="Profile not found")

    cursor.execute('SELECT profile_page FROM profiles WHERE username = ?', (username,))
    result = cursor.fetchone()
    if result is None:
        raise HTTPException(status_code=404, detail="Profile not found")

    profile_page = result[0]
    return Response(content=profile_page, media_type="text/html")

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    # Sanitize input to prevent SQL Injection (CWE-89)
    if not username.isidentifier():
        raise HTTPException(status_code=404, detail="Profile photo not found")

    cursor.execute('SELECT profile_photo_filename FROM profiles WHERE username = ?', (username,))
    result = cursor.fetchone()
    if result is None:
        raise HTTPException(status_code=404, detail="Profile photo not found")

    profile_photo_filename = result[0]
    profile_photo_path = os.path.join(PROFILE_PHOTOS_DIR, profile_photo_filename)
    
    if not os.path.exists(profile_photo_path):
        raise HTTPException(status_code=404, detail="Profile photo not found")

    return Response(content=open(profile_photo_path, "rb").read(), media_type="image/png")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)