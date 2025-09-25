import os
import sqlite3
from fastapi import FastAPI, HTTPException, Path, File, Form, UploadFile
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware
from uuid import uuid4

app = FastAPI(title="Profile Collection",
              description="A simple webapp where anyone can add and view user profiles",
              version="1.0.0")

app.add_middleware(SessionMiddleware, secret_key=os.getenv("APP_SECRET", str(uuid4())))

# Database setup
DATABASE = 'db.sqlite3'

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS profiles (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        html_content TEXT NOT NULL,
                        photo BLOB NOT NULL
                      )''')
    conn.commit()
    conn.close()

init_db()

class Profile(BaseModel):
    username: str
    profile_page: str
    profile_photo: UploadFile

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...)
):
    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG image.")
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("SELECT 1 FROM profiles WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden.")
        
        photo_data = await profile_photo.read()

        cursor.execute(
            "INSERT INTO profiles (username, html_content, photo) VALUES (?, ?, ?)",
            (username, profile_page, photo_data)
        )
        
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str = Path(..., description="The username for the profile to retrieve")):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("SELECT html_content FROM profiles WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            raise HTTPException(status_code=404, detail="Profile not found")
        
        return HTMLResponse(content=row[0], status_code=200)
    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str = Path(..., description="The username for the profile photo to retrieve")):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("SELECT photo FROM profiles WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            raise HTTPException(status_code=404, detail="Profile photo not found")
        
        return FileResponse(content=row[0], media_type='image/png')
    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail=str(e))