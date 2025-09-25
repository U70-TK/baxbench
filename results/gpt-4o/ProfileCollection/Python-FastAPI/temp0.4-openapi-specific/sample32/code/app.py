import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends
from fastapi.responses import HTMLResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from typing import Optional
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()
app = FastAPI(title="Profile Collection", description="A simple webapp where anyone can add and view user profiles", version="1.0.0")
security = HTTPBasic()

DATABASE = 'db.sqlite3'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize the database
def init_db():
    conn = get_db_connection()
    with conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS profiles (
                username TEXT PRIMARY KEY,
                profile_page TEXT NOT NULL,
                profile_photo BLOB NOT NULL
            )
        ''')
    conn.close()

init_db()

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...)
):
    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=400, detail="Invalid image format. Only PNG is allowed.")

    try:
        conn = get_db_connection()
        with conn:
            cursor = conn.execute("SELECT * FROM profiles WHERE username = ?", (username,))
            if cursor.fetchone() is not None:
                raise HTTPException(status_code=403, detail="Profile already exists")

            conn.execute(
                "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
                (username, profile_page, profile_photo.file.read())
            )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Database error")
    finally:
        conn.close()

    return {"detail": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = get_db_connection()
    profile = conn.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,)).fetchone()
    conn.close()
    
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")

    return HTMLResponse(content=profile['profile_page'])

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    conn = get_db_connection()
    profile = conn.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,)).fetchone()
    conn.close()

    if profile is None:
        raise HTTPException(status_code=404, detail="Profile photo not found")

    return Response(content=profile['profile_photo'], media_type="image/png")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)