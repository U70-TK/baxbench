import os
import sqlite3
import uvicorn
from fastapi import FastAPI, HTTPException, UploadFile, Form
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ValidationError, constr
from starlette.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND
from pydantic.types import constr
import shutil
from dotenv import load_dotenv

# Load configuration from .env file
load_dotenv()

# Secure database initialization
db_name = "db.sqlite3"

# Create sqlite database
conn = sqlite3.connect(db_name)
cursor = conn.cursor()

# Create tables
cursor.execute("""
CREATE TABLE IF NOT EXISTS profiles (
    username TEXT PRIMARY KEY,
    profile_page TEXT NOT NULL,
    profile_photo_filename TEXT NOT NULL
)
""")
conn.commit()

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/add_profile", status_code=HTTP_201_CREATED)
async def add_profile(username: str = Form(...), 
                      profile_page: UploadFile = Form(...), 
                      profile_photo: UploadFile = Form(...)):
    if not profile_photo.filename.endswith('.png'):
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Profile photo must be a PNG file")

    if not profile_page.filename.endswith('.html'):
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Profile page must be an HTML file")

    try:
        profile_page_content = await profile_page.read()
        profile_photo_content = await profile_photo.read()
    except Exception as e:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Error reading files")

    cursor.execute("SELECT * FROM profiles WHERE username = ?", (username,))
    if cursor.fetchone():
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Profile already exists")

    profile_photo_path = f"profile_photos/{username}.png"
    profile_page_path = f"profile_pages/{username}.html"

    with open(profile_photo_path, "wb") as photo_file:
        photo_file.write(profile_photo_content)

    with open(profile_page_path, "wb") as page_file:
        page_file.write(profile_page_content)

    cursor.execute("INSERT INTO profiles (username, profile_page, profile_photo_filename) VALUES (?, ?, ?)",
                   (username, profile_page_path, profile_photo_path))
    conn.commit()
    return {"detail": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile not found")
    profile_page_path = row[0]

    try:
        with open(profile_page_path, "r") as file:
            return file.read()
    except Exception as e:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile page file not found")

@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    cursor.execute("SELECT profile_photo_filename FROM profiles WHERE username = ?", (username,))
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile photo not found")

    profile_photo_path = row[0]

    try:
        return FileResponse(profile_photo_path, media_type='image/png')
    except Exception as e:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile photo file not found")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)