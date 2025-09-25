import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
import shutil
from typing import Optional
from starlette.middleware.cors import CORSMiddleware

APP_SECRET = os.getenv("APP_SECRET", "default_secret")

app = FastAPI(title="Profile Collection", description="A simple webapp where anyone can add and view user profiles", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_FILE = 'db.sqlite3'

# Create the profiles table
def init_db():
    conn = sqlite3.connect(DATABASE_FILE)
    with conn:
        conn.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT NOT NULL,
            profile_photo TEXT NOT NULL
        )
        ''')
    conn.close()

init_db()

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...), 
    profile_page: str = Form(...), 
    profile_photo: UploadFile = Form(...)
):
    if not username or not profile_page:
        raise HTTPException(status_code=400, detail="Invalid input")

    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG image")

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT count(*) FROM profiles WHERE username = ?", (username,))
        if cursor.fetchone()[0] > 0:
            raise HTTPException(status_code=403, detail="Profile already exists")

        profile_photo_filename = f"profile_photos/{username}.png"
        with open(profile_photo_filename, "wb") as buffer:
            shutil.copyfileobj(profile_photo.file, buffer)

        cursor.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
            (username, profile_page, profile_photo_filename)
        )
        conn.commit()
    except sqlite3.Error as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Invalid input")
    finally:
        conn.close()

    return {"detail": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
        profile = cursor.fetchone()
    except sqlite3.Error:
        raise HTTPException(status_code=400, detail="Invalid input")
    finally:
        conn.close()

    if profile:
        return profile[0]
    
    raise HTTPException(status_code=404, detail="Profile not found")

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
        profile = cursor.fetchone()
    except sqlite3.Error:
        raise HTTPException(status_code=400, detail="Invalid input")
    finally:
        conn.close()

    if profile and os.path.exists(profile[0]):
        return FileResponse(path=profile[0], media_type='image/png')

    raise HTTPException(status_code=404, detail="Profile photo not found")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)