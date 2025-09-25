import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form, Depends, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
from fastapi.security.api_key import APIKeyHeader
from starlette.middleware.cors import CORSMiddleware
import shutil
from pathlib import Path
from dotenv import load_dotenv
import uvicorn
from typing import Optional

load_dotenv()

# Load the application secret from environment variables
APP_SECRET = os.getenv('APP_SECRET', 'defaultsecret')

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

# Security: use an API key scheme (can be improved considering different auth requirements)
api_key_header = APIKeyHeader(name='X-API-KEY', auto_error=False)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust according to your CORS needs
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE = "db.sqlite3"
IMG_FOLDER = Path("images")
IMG_FOLDER.mkdir(exist_ok=True)

# Database initialization
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS profiles (
                username TEXT PRIMARY KEY,
                profile_page TEXT NOT NULL,
                profile_photo BLOB NOT NULL
            )
        ''')
    conn.close()

# Dependency to get API key
async def get_api_key(
    api_key: Optional[str] = Depends(api_key_header)
):
    if api_key != APP_SECRET:
        raise HTTPException(status_code=403, detail="Could not validate credentials")
    return api_key

@app.on_event("startup")
async def startup():
    init_db()

class ProfileIn(BaseModel):
    username: str
    profile_page: str
    profile_photo: UploadFile

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = Form(...),
):
    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG image")

    html_content = profile_page

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM profiles WHERE username = ?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists")

        file_location = IMG_FOLDER / f"{username}.png"
        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(profile_photo.file, buffer)

        cursor.execute(
            '''INSERT INTO profiles (username, profile_page, profile_photo)
               VALUES (?, ?, ?)''',
            (username, html_content, profile_photo.filename)
        )
        conn.commit()
    conn.close()

    return {"detail": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
        row = cursor.fetchone()
    conn.close()

    if row:
        return row[0]
    else:
        raise HTTPException(status_code=404, detail="Profile not found")

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str, request: Request):
    response_headers = {
        "Cache-Control": "max-age=3600, public",
    }

    file_location = IMG_FOLDER / f"{username}.png"
    if file_location.exists():
        return StreamingResponse(file_location.open("rb"), media_type="image/png", headers=response_headers)
    else:
        raise HTTPException(status_code=404, detail="Profile photo not found")

if __name__ == "__main__":
    uvicorn.run(app, host='0.0.0.0', port=5000)