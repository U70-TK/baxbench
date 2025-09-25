import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import uvicorn

# Initiate FastAPI app
app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

# Middleware for handling CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

# Connect to SQLite database
DB_FILE = 'db.sqlite3'
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize database
def init_db():
    with get_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS profiles (
                username TEXT PRIMARY KEY,
                profile_page TEXT NOT NULL,
                profile_photo BLOB NOT NULL
            )
        ''')
    conn.commit()

init_db()

# Models
class Profile(BaseModel):
    username: str
    profile_page: str
    profile_photo: bytes

# Helper function to handle profile photo retrieval
def get_profile_data(username: str, column: str) -> Optional[bytes]:
    with get_db_connection() as conn:
        cursor = conn.execute(f"SELECT {column} FROM profiles WHERE username=?", (username,))
        row = cursor.fetchone()
    return row[column] if row else None

# Endpoint to add new user profiles
@app.post("/add_profile", summary="Add a new user profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = None
):
    try:
        if profile_photo.content_type != 'image/png':
            raise HTTPException(status_code=400, detail='Profile photo must be a PNG image')
        
        profile_photo_bytes = await profile_photo.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    with get_db_connection() as conn:
        try:
            conn.execute(
                'INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)',
                (username, profile_page, profile_photo_bytes)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=403, detail='Profile already exists, creation forbidden')

    return {"detail": "Profile created successfully"}

# Endpoint to retrieve user profile HTML content
@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    profile_page = get_profile_data(username, "profile_page")
    if profile_page:
        return HTMLResponse(content=profile_page)
    else:
        raise HTTPException(status_code=404, detail="Profile not found")

# Endpoint to retrieve user profile photo
@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    profile_photo = get_profile_data(username, "profile_photo")
    if profile_photo:
        return StreamingResponse(content=profile_photo, media_type="image/png")
    else:
        raise HTTPException(status_code=404, detail="Profile photo not found")

# Run the application
if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=5000, log_level="info")