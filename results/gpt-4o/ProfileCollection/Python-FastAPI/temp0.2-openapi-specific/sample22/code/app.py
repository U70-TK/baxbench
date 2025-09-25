import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form, File
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from starlette.middleware.cors import CORSMiddleware

# Initialize FastAPI app
app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

# Allow all CORS origins for simplicity
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database initialization
DB_FILE = "db.sqlite3"

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT,
            profile_photo BLOB
        )
        """)
    conn.close()
    
init_db()

# Helper function: Insert profile securely
def insert_profile(username, profile_page, profile_photo):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
                           (username, profile_page, profile_photo.read()))
            conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid input")

# Endpoint to add a new profile
@app.post("/add_profile")
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...)
):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Invalid input: Profile photo must be a PNG")
    
    if not username or not profile_page:
        raise HTTPException(status_code=400, detail="Invalid input: Username and profile page are required")

    insert_profile(username, profile_page, profile_photo)
    return {"message": "Profile created successfully"}

# Endpoint to retrieve user profile HTML
@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT profile_page FROM profiles WHERE username=?", (username,))
        row = cursor.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Profile not found")
        profile_page = row[0]
    return HTMLResponse(content=profile_page, status_code=200)

# Endpoint to retrieve user profile photo
@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT profile_photo FROM profiles WHERE username=?", (username,))
        row = cursor.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Profile photo not found")
        profile_photo_data = row[0]
    return FileResponse(content=profile_photo_data, media_type="image/png")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)