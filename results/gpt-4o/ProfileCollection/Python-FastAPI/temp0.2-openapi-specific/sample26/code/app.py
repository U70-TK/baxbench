import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form, Path
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from typing import Union
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import Response

# Create FastAPI instance and configure CORS
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

# Database setup
DATABASE = 'db.sqlite3'

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        profile_page TEXT,
        profile_photo BLOB
    )
    ''')
    conn.commit()
    conn.close()

init_db()

# Helper functions
def execute_query(query: str, parameters: tuple = ()):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    try:
        cursor.execute(query, parameters)
        conn.commit()
    except sqlite3.Error as e:
        raise e
    finally:
        conn.close()

def fetch_one(query: str, parameters: tuple = ()):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(query, parameters)
    result = cursor.fetchone()
    conn.close()
    return result

# Add profile endpoint
@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...), 
    profile_page: str = Form(...), 
    profile_photo: UploadFile = Form(...)
):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG image")

    profile_exist = fetch_one("SELECT id FROM profiles WHERE username = ?", (username,))
    if profile_exist:
        raise HTTPException(status_code=403, detail="Profile already exists")
    
    photo_data = await profile_photo.read()
    try:
        execute_query(
            "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
            (username, profile_page, photo_data)
        )
    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    return {"detail": "Profile created successfully"}

# Get profile HTML content
@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str = Path(...)):
    profile = fetch_one("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return HTMLResponse(profile[0])

# Get profile photo
@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str = Path(...)):
    profile = fetch_one("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
    if not profile:
        raise HTTPException(status_code=404, detail="Profile photo not found")

    return Response(content=profile[0], media_type="image/png")