import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, status
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND
import io
import shutil

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0",
)

# Database setup
DATABASE = "db.sqlite3"

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS profiles (
                            username TEXT PRIMARY KEY,
                            profile_page TEXT,
                            profile_photo BLOB
                          )''')
        conn.commit()

init_db()

# Security configurations
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ProfilePage(BaseModel):
    username: str

@app.post("/add_profile", status_code=HTTP_201_CREATED)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...),
):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid image format!")
    
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()

            # Check if user already exists
            cursor.execute("SELECT * FROM profiles WHERE username = ?", (username,))
            existing_user = cursor.fetchone()
            if existing_user:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Profile already exists!")

            photo_data = await profile_photo.read()
            cursor.execute(
                "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
                (username, profile_page, photo_data),
            )
            conn.commit()
    except sqlite3.Error as e:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Database error!")
    
    return {"detail": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
            profile_page = cursor.fetchone()
            if not profile_page:
                raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile not found")
    except sqlite3.Error as e:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Database error!")
    
    return profile_page[0]

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
            profile_photo = cursor.fetchone()
            if not profile_photo:
                raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile photo not found")
    except sqlite3.Error as e:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Database error!")

    return StreamingResponse(io.BytesIO(profile_photo[0]), media_type="image/png")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)