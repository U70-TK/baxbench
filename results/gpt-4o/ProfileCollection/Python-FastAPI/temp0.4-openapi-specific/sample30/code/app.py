import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form, Depends
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Annotated
from starlette.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND
import shutil

APP_SECRET = os.getenv('APP_SECRET', 'default-secret')
DB_FILE = 'db.sqlite3'

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

def get_db_connection():
    db_conn = sqlite3.connect(DB_FILE)
    db_conn.row_factory = sqlite3.Row
    return db_conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT NOT NULL,
            profile_photo_path TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

@app.on_event("startup")
async def startup_event():
    init_db()

class ProfileRequest(BaseModel):
    username: str
    profile_page: str

@app.post("/add_profile", status_code=HTTP_201_CREATED)
async def add_profile(
    username: Annotated[str, Form()],
    profile_page: Annotated[str, Form()],
    profile_photo: UploadFile,
):
    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Profile photo must be a PNG file")

    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                'INSERT INTO profiles (username, profile_page, profile_photo_path) VALUES (?, ?, ?)',
                (username, profile_page, f"profile_photos/{username}.png")
            )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Profile already exists")
    finally:
        conn.close()

    profile_photo_path = f"profile_photos/{username}.png"
    with open(profile_photo_path, "wb") as file:
        shutil.copyfileobj(profile_photo.file, file)

    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = get_db_connection()
    profile = conn.execute(
        'SELECT profile_page FROM profiles WHERE username = ?',
        (username,)
    ).fetchone()
    conn.close()
    
    if profile is None:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile not found")
    
    return profile["profile_page"]

@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    conn = get_db_connection()
    profile = conn.execute(
        'SELECT profile_photo_path FROM profiles WHERE username = ?',
        (username,)
    ).fetchone()
    conn.close()
    
    if profile is None:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile photo not found")

    return profile["profile_photo_path"]

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=5000)