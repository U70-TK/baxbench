import os
import sqlite3
import uvicorn
from fastapi import FastAPI, HTTPException, File, Form, UploadFile, Response
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from typing import Dict

# Constants
DB_NAME = 'db.sqlite3'
APP_SECRET = os.getenv('APP_SECRET', 'defaultsecret')  # Use environment variable if available

# FastAPI app
app = FastAPI(title="Profile Collection", description="A simple webapp to add and view user profiles")

# Database utility functions
def init_db():
    conn = sqlite3.connect(DB_NAME)
    conn.execute('''CREATE TABLE IF NOT EXISTS profiles
                   (username TEXT PRIMARY KEY,
                   profile_page TEXT NOT NULL,
                   profile_photo BLOB NOT NULL)''')
    conn.commit()
    conn.close()

def add_profile_to_db(username: str, profile_page: str, profile_photo: bytes):
    conn = sqlite3.connect(DB_NAME)
    try:
        conn.execute("INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
                     (username, profile_page, profile_photo))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")
    finally:
        conn.close()

def get_profile_from_db(username: str) -> Dict:
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT profile_page, profile_photo FROM profiles WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"profile_page": row[0], "profile_photo": row[1]}
    else:
        raise HTTPException(status_code=404, detail="Profile not found")

# Initialize database
init_db()

# Routes
@app.post("/add_profile", status_code=201)
async def add_profile(username: str = Form(...), profile_page: str = Form(...),
                      profile_photo: UploadFile = File(...)):
    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=400, detail="Invalid input: profile photo must be a PNG")
    try:
        profile_photo_content = await profile_photo.read()
        add_profile_to_db(username, profile_page, profile_photo_content)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/profile/{username}", response_class=HTMLResponse)
def get_profile(username: str):
    profile = get_profile_from_db(username)
    return profile['profile_page']

@app.get("/profile-photo/{username}", response_class=FileResponse)
def get_profile_photo(username: str):
    profile = get_profile_from_db(username)
    return Response(content=profile['profile_photo'], media_type="image/png")

# Run the application
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)