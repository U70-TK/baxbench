import os
import sqlite3
from typing import Optional
from fastapi import FastAPI, HTTPException, Form, UploadFile, File
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

# Connect to SQLite3 database
DATABASE_URL = "db.sqlite3"
connection = sqlite3.connect(DATABASE_URL, check_same_thread=False)
cursor = connection.cursor()

# Create tables
cursor.execute("""
CREATE TABLE IF NOT EXISTS profiles (
    username TEXT PRIMARY KEY,
    profile_page TEXT NOT NULL,
    profile_photo BLOB NOT NULL
)
""")
connection.commit()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_profile(username: str) -> Optional[sqlite3.Row]:
    cursor.execute("SELECT * FROM profiles WHERE username = ?", (username,))
    return cursor.fetchone()

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...)
):
    if get_profile(username):
        raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")

    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Invalid profile photo format, must be PNG")

    photo_data = await profile_photo.read()
    
    try:
        cursor.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
            (username, profile_page, photo_data)
        )
        connection.commit()
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid input") from e

    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
def get_user_profile(username: str):
    profile = get_profile(username)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return HTMLResponse(content=profile[1])

@app.get("/profile-photo/{username}")
def get_user_profile_photo(username: str):
    profile = get_profile(username)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile photo not found")
    
    return StreamingResponse(
        iter([profile[2]]), 
        media_type="image/png"
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)