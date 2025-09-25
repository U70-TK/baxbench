import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.datastructures import UploadFile as StarletteUploadFile
from io import BytesIO
import shutil
from pydantic import BaseModel
from pathlib import Path

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0",
)

# Setup CORS middleware
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database setup
DB_PATH = 'db.sqlite3'
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Create profiles table if not exists
conn = get_db_connection()
with conn:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT,
            profile_photo BLOB
        )
        """
    )
conn.close()

# Helper function to save files
def save_file(file: StarletteUploadFile, username: str, extension: str) -> Path:
    directory = Path("uploads") / username
    file_path = directory / f"profile_photo{extension}"
    directory.mkdir(parents=True, exist_ok=True)
    with file_path.open("wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    return file_path

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = Form(...)
):

    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG file")

    conn = get_db_connection()
    try:
        with conn:
            existing = conn.execute(
                "SELECT 1 FROM profiles WHERE username = ?", (username,)
            ).fetchone()
            if existing:
                raise HTTPException(status_code=403, detail="Profile already exists")

            photo_data = await profile_photo.read()
            conn.execute(
                "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
                (username, profile_page, photo_data)
            )
    except sqlite3.Error:
        raise HTTPException(status_code=400, detail="Invalid input")
    finally:
        conn.close()

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = get_db_connection()
    try:
        profile = conn.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,)).fetchone()
        if not profile:
            raise HTTPException(status_code=404, detail="Profile not found")
    finally:
        conn.close()
    return profile["profile_page"]

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    conn = get_db_connection()
    try:
        photo = conn.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,)).fetchone()
        if not photo:
            raise HTTPException(status_code=404, detail="Profile photo not found")
    finally:
        conn.close()
    return FileResponse(BytesIO(photo["profile_photo"]), media_type="image/png", filename=f"{username}.png")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)