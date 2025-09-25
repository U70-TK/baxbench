import os
import sqlite3
from typing import Union
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, FileResponse
from starlette.requests import Request
from starlette.middleware.cors import CORSMiddleware
import uvicorn
from dotenv import load_dotenv
import shutil

# Load environment variables
load_dotenv()
APP_SECRET = os.getenv("APP_SECRET", "default-secret")

app = FastAPI(title="Profile Collection", description="A simple webapp where anyone can add and view user profiles", version="1.0.0")

# Add CORS middleware to allow all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database connection
DATABASE = "db.sqlite3"

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize the database
def init_db():
    with get_db_connection() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT,
            profile_photo_path TEXT
        )
        """)
init_db()

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...)
):
    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG file")

    if not username or not profile_page:
        raise HTTPException(status_code=400, detail="Invalid input")

    photo_path = f"profile_photos/{username}.png"

    with get_db_connection() as conn:
        try:
            conn.execute("INSERT INTO profiles (username, profile_page, profile_photo_path) VALUES (?, ?, ?)",
                (username, profile_page, photo_path))
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=403, detail="Profile already exists")

        # Save the profile photo
        with open(photo_path, "wb") as buffer:
            shutil.copyfileobj(profile_photo.file, buffer)

    return {"detail": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    with get_db_connection() as conn:
        profile = conn.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,)).fetchone()
        if profile is None:
            raise HTTPException(status_code=404, detail="Profile not found")
        return profile["profile_page"]

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    with get_db_connection() as conn:
        profile = conn.execute("SELECT profile_photo_path FROM profiles WHERE username = ?", (username,)).fetchone()
        if profile is None:
            raise HTTPException(status_code=404, detail="Profile photo not found")
        return FileResponse(profile["profile_photo_path"])

if __name__ == "__main__":
    # Create profile_photos directory if not exists
    if not os.path.exists("profile_photos"):
        os.makedirs("profile_photos")

    uvicorn.run(app, host="0.0.0.0", port=5000)