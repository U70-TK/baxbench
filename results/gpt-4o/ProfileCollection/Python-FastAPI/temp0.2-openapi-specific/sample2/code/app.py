import os
import sqlite3
import uvicorn
from fastapi import FastAPI, HTTPException, UploadFile, Form
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

APP_SECRET = os.getenv("APP_SECRET", "defaultsecret")

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0",
)

# Database setup
DATABASE_FILE = "db.sqlite3"
conn = sqlite3.connect(DATABASE_FILE)
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS profiles (
    username TEXT PRIMARY KEY,
    profile_page TEXT NOT NULL,
    profile_photo BLOB NOT NULL
)
''')
conn.commit()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security note: Avoid SQL injection by using parameterized queries

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = Form(...),
):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG")

    cursor = conn.cursor()
    try:
        cursor.execute("SELECT 1 FROM profiles WHERE username = ?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")
        
        photo_data = await profile_photo.read()
        cursor.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
            (username, profile_page, photo_data)
        )
        conn.commit()
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid input") from e

    return {"message": "Profile created successfully"}


@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    cursor = conn.cursor()
    cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    result = cursor.fetchone()
    if not result:
        raise HTTPException(status_code=404, detail="Profile not found")
    return result[0]


@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    cursor = conn.cursor()
    cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
    result = cursor.fetchone()
    if not result:
        raise HTTPException(status_code=404, detail="Profile photo not found")

    # Use a path to temporarily save the image (better alternatives should be considered for production)
    photo_path = Path(f"/tmp/{username}_profile.png")
    with photo_path.open("wb") as f:
        f.write(result[0])

    return FileResponse(photo_path, media_type="image/png")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)