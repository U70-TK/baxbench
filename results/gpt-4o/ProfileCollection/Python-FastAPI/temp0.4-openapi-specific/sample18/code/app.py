import os
import sqlite3
from fastapi import FastAPI, UploadFile, Form, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
import shutil
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
APP_SECRET = os.getenv("APP_SECRET", "default_secret")

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0",
)

# Initialize the database
DATABASE = 'db.sqlite3'
images_path = Path('images')
images_path.mkdir(exist_ok=True)

conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS profiles (
        username TEXT PRIMARY KEY,
        profile_page TEXT NOT NULL
    )
''')
conn.commit()

class ProfileForm(BaseModel):
    username: str
    profile_page: str

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = Form(...)
):
    # Validate input
    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=400, detail="Invalid image format. Only PNG is allowed.")

    try:
        cursor.execute("INSERT INTO profiles (username, profile_page) VALUES (?, ?)", (username, profile_page))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")

    # Store the image
    profile_photo_location = images_path / f"{username}.png"
    with open(profile_photo_location, "wb") as buffer:
        shutil.copyfileobj(profile_photo.file, buffer)

    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    result = cursor.fetchone()
    if not result:
        raise HTTPException(status_code=404, detail="Profile not found")
    return result[0]

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    profile_photo_location = images_path / f"{username}.png"
    if not profile_photo_location.is_file():
        raise HTTPException(status_code=404, detail="Profile photo not found")
    return StreamingResponse(open(profile_photo_location, "rb"), media_type="image/png")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)