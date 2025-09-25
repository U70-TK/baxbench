from fastapi import FastAPI, HTTPException, UploadFile, Form
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import sqlite3
import os
import uvicorn
from typing import Annotated
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

DATABASE = 'db.sqlite3'

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT,
            profile_photo BLOB
        )
    ''')
    conn.commit()
    conn.close()

@app.post("/add_profile", summary="Add a new user profile")
async def add_profile(
    username: Annotated[str, Form()],
    profile_page: Annotated[UploadFile, Form()],
    profile_photo: Annotated[UploadFile, Form()]
):
    if profile_page.content_type != 'text/html' or profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=400, detail="Invalid input")
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT COUNT(*) FROM profiles WHERE username = ?", (username,))
        if cursor.fetchone()[0] > 0:
            raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")
        
        profile_page_content = await profile_page.read()
        profile_photo_content = await profile_photo.read()
        
        cursor.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
            (username, profile_page_content.decode('utf-8'), profile_photo_content)
        )
        conn.commit()
    except sqlite3.Error as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()
    
    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse, summary="Get user profile")
async def get_profile(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result is None:
            raise HTTPException(status_code=404, detail="Profile not found")
        
        return result[0]
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()

@app.get("/profile-photo/{username}", summary="Get user profile photo")
async def get_profile_photo(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result is None:
            raise HTTPException(status_code=404, detail="Profile photo not found")
        
        return FileResponse(result[0], media_type='image/png')
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()

if __name__ == "__main__":
    init_db()
    uvicorn.run(app, host="0.0.0.0", port=5000)