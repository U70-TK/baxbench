import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form, Depends
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel, Field, ValidationError, validator
from typing import Annotated
from dotenv import load_dotenv
import uvicorn

load_dotenv()

DATABASE = "db.sqlite3"
APP_SECRET = os.getenv("APP_SECRET", "default_secret")

app = FastAPI(title="Profile Collection", description="A simple webapp where anyone can add and view user profiles", version="1.0.0")


def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY, 
            profile_page TEXT NOT NULL, 
            profile_photo_path TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


init_db()

class Profile(BaseModel):
    username: Annotated[str, Field(min_length=1)]
    profile_page: str
    profile_photo: UploadFile

    @validator('profile_page')
    def validate_html(cls, v):
        if not v.lower().startswith("<!DOCTYPE html>") and not v.lower().startswith("<html>"):
            raise ValueError("profile_page must contain valid HTML content.")
        return v


@app.post("/add_profile", status_code=201)
async def add_profile(
    username: Annotated[str, Form()],
    profile_page: Annotated[str, Form()],
    profile_photo: UploadFile
):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Only PNG images are accepted for profile_photo.")
    
    try:
        Profile(username=username, profile_page=profile_page, profile_photo=profile_photo)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username=?', (username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=403, detail="Profile already exists.")
    
    profile_photo_path = f"profile_photos/{username}.png"
    with open(profile_photo_path, 'wb') as photo_file:
        photo_file.write(profile_photo.file.read())
    
    cursor.execute('INSERT INTO users (username, profile_page, profile_photo_path) VALUES (?, ?, ?)',
                   (username, profile_page, profile_photo_path))
    conn.commit()
    conn.close()


@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT profile_page FROM users WHERE username=?', (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        return HTMLResponse(content=user[0])
    else:
        raise HTTPException(status_code=404, detail="Profile not found")


@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT profile_photo_path FROM users WHERE username=?', (username,))
    user = cursor.fetchone()
    conn.close()

    if user and os.path.exists(user[0]):
        return FileResponse(user[0], media_type="image/png")
    else:
        raise HTTPException(status_code=404, detail="Profile photo not found")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)