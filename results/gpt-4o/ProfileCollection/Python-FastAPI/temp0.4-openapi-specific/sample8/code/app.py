import os
import sqlite3
from fastapi import FastAPI, UploadFile, Form, HTTPException, Response
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from typing import Optional
from pathlib import Path
from starlette.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND, HTTP_403_FORBIDDEN

DATABASE_FILE = "db.sqlite3"
APP_SECRET = os.getenv("APP_SECRET", "default_secret")

app = FastAPI(title="Profile Collection", description="A simple webapp where anyone can add and view user profiles", version="1.0.0")

class UserProfile(BaseModel):
    username: str
    profile_page: str
    profile_photo: bytes

def initialize_database():
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT NOT NULL,
            profile_photo BLOB NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

initialize_database()

@app.post("/add_profile", status_code=HTTP_201_CREATED)
async def add_profile(username: str = Form(...), profile_page: str = Form(...), profile_photo: UploadFile = Form(...)):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Profile photo must be a PNG image.")
    
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    
    try:
        c.execute("SELECT username FROM profiles WHERE username=?", (username,))
        if c.fetchone() is not None:
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Profile already exists.")
        
        photo_data = await profile_photo.read()
        c.execute("INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
                  (username, profile_page, photo_data))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Error processing request.")
    finally:
        conn.close()

    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    
    try:
        c.execute("SELECT profile_page FROM profiles WHERE username=?", (username,))
        row = c.fetchone()
        if row is None:
            raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile not found.")
        return Response(content=row[0], media_type="text/html")
    finally:
        conn.close()

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    
    try:
        c.execute("SELECT profile_photo FROM profiles WHERE username=?", (username,))
        row = c.fetchone()
        if row is None:
            raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile photo not found.")
        return Response(content=row[0], media_type="image/png")
    finally:
        conn.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)