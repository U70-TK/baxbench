import os
import sqlite3
from fastapi import FastAPI, HTTPException, File, UploadFile, Form
from fastapi.responses import HTMLResponse, FileResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from starlette.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND
import dotenv

dotenv.load_dotenv()

# Initialize FastAPI app
app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

# Allow CORS for all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Constants
DB_NAME = "db.sqlite3"
PROFILE_PHOTO_PATH = "./profile_photos"
APP_SECRET = os.getenv("APP_SECRET", "default-secret")

# Utility functions
def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        # Create profiles table if not exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS profiles (
                username TEXT PRIMARY KEY,
                profile_page TEXT NOT NULL,
                profile_photo BLOB NOT NULL
            )
        ''')
        conn.commit()

def insert_profile(username: str, profile_page: str, profile_photo: bytes):
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO profiles (username, profile_page, profile_photo) 
                VALUES (?, ?, ?)
            ''', (username, profile_page, profile_photo))
            conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Profile already exists")

def get_profile(username: str) -> Optional[tuple]:
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT profile_page, profile_photo FROM profiles WHERE username = ?', (username,))
        return cursor.fetchone()

# Initialize database
init_db()

# Routes
@app.post("/add_profile", status_code=HTTP_201_CREATED)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...)
):
    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid input, profile photo must be PNG")

    try:
        profile_photo_data = await profile_photo.read()
        insert_profile(username, profile_page, profile_photo_data)
    except Exception as e:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid input")

    return PlainTextResponse("Profile created successfully", status_code=HTTP_201_CREATED)

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_user_profile(username: str):
    profile = get_profile(username)
    if not profile:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile not found")

    return profile[0]

@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_user_profile_photo(username: str):
    profile = get_profile(username)
    if not profile:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile photo not found")
    
    profile_photo_data = profile[1]
    photo_path = f"{PROFILE_PHOTO_PATH}/{username}.png"
    
    # Save the profile photo temporarily to serve it
    os.makedirs(PROFILE_PHOTO_PATH, exist_ok=True)
    with open(photo_path, "wb") as photo_file:
        photo_file.write(profile_photo_data)

    return photo_path

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)