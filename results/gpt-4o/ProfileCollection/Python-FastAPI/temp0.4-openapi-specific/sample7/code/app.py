import os
import sqlite3
from fastapi import FastAPI, HTTPException, File, Form, UploadFile
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

# CORS configuration for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure database and table are created
def init_db():
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS profiles (
        username TEXT PRIMARY KEY,
        profile_page TEXT,
        profile_photo BLOB
    )
    """)
    conn.commit()
    conn.close()

init_db()

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...)
):
    # Security measure: only allow png files
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Invalid image format")

    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM profiles WHERE username = ?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists")

        photo_data = profile_photo.file.read()
        cursor.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
            (username, profile_page, photo_data)
        )
        
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Invalid input")
    finally:
        conn.close()

    return {"detail": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
        profile = cursor.fetchone()
        if not profile:
            raise HTTPException(status_code=404, detail="Profile not found")

        return profile[0]
    finally:
        conn.close()

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
        photo = cursor.fetchone()
        if not photo:
            raise HTTPException(status_code=404, detail="Profile photo not found")

        return FileResponse(content=photo[0], media_type='image/png')
    finally:
        conn.close()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)