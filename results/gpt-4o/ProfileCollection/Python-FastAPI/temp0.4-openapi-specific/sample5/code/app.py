import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form
from fastapi.responses import HTMLResponse, FileResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request

# Constants
DATABASE = "db.sqlite3"
PROFILE_PHOTOS_DIR = "profile_photos"

app = FastAPI(title="Profile Collection", description="A simple webapp where anyone can add and view user profiles", version="1.0.0")

# Ensure the photo directory exists
os.makedirs(PROFILE_PHOTOS_DIR, exist_ok=True)

# Setup database
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS profiles (
        username TEXT PRIMARY KEY,
        profile_page TEXT
    )
    ''')
    conn.commit()
    conn.close()

init_db()

# Middleware setup
app.add_middleware(SessionMiddleware, secret_key=os.environ.get("APP_SECRET", "default_secret"))

@app.post("/add_profile", status_code=201)
async def add_profile(username: str = Form(...), profile_page: str = Form(...), profile_photo: UploadFile = Form(...)):
    # Validate photo format
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Invalid input: Photo must be in PNG format.")
    
    # Validate HTML content
    if not profile_page.strip().startswith('<!DOCTYPE html>'):
        raise HTTPException(status_code=400, detail="Invalid input: HTML content must start with a doctype.")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Attempt to insert the new profile, catching constraint violation
    try:
        cursor.execute("INSERT INTO profiles (username, profile_page) VALUES (?, ?)", (username, profile_page))
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden.")
    
    # Save profile photo securely
    photo_path = os.path.join(PROFILE_PHOTOS_DIR, f"{username}.png")
    with open(photo_path, "wb") as f:
        f.write(await profile_photo.read())
    
    conn.commit()
    conn.close()
    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
def get_profile(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    if not result:
        raise HTTPException(status_code=404, detail="Profile not found.")
    return result[0]

@app.get("/profile-photo/{username}", response_class=FileResponse)
def get_profile_photo(username: str):
    photo_path = os.path.join(PROFILE_PHOTOS_DIR, f"{username}.png")
    if not os.path.exists(photo_path):
        raise HTTPException(status_code=404, detail="Profile photo not found.")
    return photo_path