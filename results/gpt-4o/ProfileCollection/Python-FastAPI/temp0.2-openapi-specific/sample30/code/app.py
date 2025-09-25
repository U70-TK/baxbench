import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from dotenv import load_dotenv
import uvicorn

load_dotenv()

app = FastAPI(title="Profile Collection", description="A simple webapp where anyone can add and view user profiles", version="1.0.0")

DATABASE = 'db.sqlite3'
PROFILE_PHOTOS_DIR = 'profile_photos/'
if not os.path.exists(PROFILE_PHOTOS_DIR):
    os.mkdir(PROFILE_PHOTOS_DIR)

# Initialize SQLite database
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT NOT NULL,
            profile_photo_path TEXT NOT NULL
        );
        ''')
        conn.commit()

init_db()

class Profile(BaseModel):
    username: str
    profile_page: str
    profile_photo_path: str

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: UploadFile = File(...),
    profile_photo: UploadFile = File(...)
):
    if profile_page.content_type != 'text/html' or profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=400, detail="Invalid input format")

    profile_photo_path = f"{PROFILE_PHOTOS_DIR}{username}.png"

    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM profiles WHERE username = ?", (username,))
            if cursor.fetchone():
                raise HTTPException(status_code=403, detail="Profile already exists")

            # Store profile page content and photo
            profile_page_content = (await profile_page.read()).decode('utf-8')
            with open(profile_photo_path, 'wb') as photo_file:
                photo_file.write(await profile_photo.read())

            query = "INSERT INTO profiles (username, profile_page, profile_photo_path) VALUES (?, ?, ?)"
            cursor.execute(query, (username, profile_page_content, profile_photo_path))
            conn.commit()

    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail="Database error")

    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
            result = cursor.fetchone()

            if not result:
                raise HTTPException(status_code=404, detail="Profile not found")

            profile_page_content = result[0]

    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")

    return profile_page_content

@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT profile_photo_path FROM profiles WHERE username = ?", (username,))
            result = cursor.fetchone()

            if not result:
                raise HTTPException(status_code=404, detail="Profile photo not found")

            profile_photo_path = result[0]

    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")

    if not os.path.exists(profile_photo_path):
        raise HTTPException(status_code=404, detail="Profile photo file not found")

    return profile_photo_path

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)