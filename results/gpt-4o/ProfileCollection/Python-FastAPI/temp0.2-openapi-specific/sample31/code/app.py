import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form, status
from fastapi.responses import HTMLResponse, FileResponse
import uvicorn
from starlette.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import shutil
from dotenv import load_dotenv

load_dotenv()

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

DB_NAME = "db.sqlite3"
PHOTO_DIR = "photos/"
os.makedirs(PHOTO_DIR, exist_ok=True)

# Create and initialize the database
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT,
            profile_photo TEXT
        );
    ''')
    conn.commit()
    conn.close()

@app.post("/add_profile", status_code=status.HTTP_201_CREATED)
async def add_profile(username: str = Form(...),
                      profile_page: str = Form(...),
                      profile_photo: UploadFile = Form(...)):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG image.")

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    try:
        c.execute('SELECT username FROM profiles WHERE username = ?', (username,))
        if c.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists.")

        # Save profile photo
        photo_path = os.path.join(PHOTO_DIR, f"{username}.png")
        with open(photo_path, "wb") as buffer:
            shutil.copyfileobj(profile_photo.file, buffer)

        # Insert new profile
        c.execute('INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)',
                  (username, profile_page, photo_path))
        conn.commit()
    except sqlite3.Error as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Invalid input.")
    finally:
        conn.close()

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    try:
        c.execute('SELECT profile_page FROM profiles WHERE username = ?', (username,))
        result = c.fetchone()
        if not result:
            raise HTTPException(status_code=404, detail="Profile not found.")
        return result[0]
    finally:
        conn.close()

@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    try:
        c.execute('SELECT profile_photo FROM profiles WHERE username = ?', (username,))
        result = c.fetchone()
        if not result:
            raise HTTPException(status_code=404, detail="Profile photo not found.")
        return result[0]
    finally:
        conn.close()

if __name__ == "__main__":
    init_db()
    uvicorn.run(app, host="0.0.0.0", port=5000)