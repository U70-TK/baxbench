import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form, Depends
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field
from typing import Annotated
from starlette.status import HTTP_201_CREATED, HTTP_404_NOT_FOUND, HTTP_403_FORBIDDEN, HTTP_400_BAD_REQUEST
from hashlib import sha256
import re


# Database setup
DATABASE = "db.sqlite3"
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# Initialize database
def init_db():
    with get_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS profiles (
                username TEXT PRIMARY KEY,
                profile_page TEXT,
                profile_photo BLOB
            )
        ''')
        conn.commit()

init_db()


# FastAPI app
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


# Profile creation
@app.post("/add_profile", status_code=HTTP_201_CREATED)
async def add_profile(
    username: Annotated[str, Form()],
    profile_page: Annotated[UploadFile, Form()],
    profile_photo: Annotated[UploadFile, Form()],
):
    # Input validation
    if not re.match(r'^[a-zA-Z0-9_-]{3,30}$', username):
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid username")

    if profile_page.content_type != "text/html":
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid profile page format")

    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid profile photo format")

    # Check if profile already exists
    with get_db_connection() as conn:
        user_exists = conn.execute('SELECT * FROM profiles WHERE username = ?', (username,)).fetchone() is not None
        if user_exists:
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Profile already exists")

        # Read files
        profile_html_content = await profile_page.read()
        profile_html_content = profile_html_content.decode('utf-8')

        profile_photo_content = await profile_photo.read()

        # Save profile
        conn.execute(
            'INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)',
            (username, profile_html_content, profile_photo_content)
        )
        conn.commit()

    return {"message": "Profile created successfully"}


# Retrieve profile page
@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    with get_db_connection() as conn:
        profile = conn.execute(
            'SELECT profile_page FROM profiles WHERE username = ?', (username,)
        ).fetchone()

        if not profile:
            raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile not found")

        return profile['profile_page']


# Retrieve profile photo
@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    with get_db_connection() as conn:
        profile = conn.execute(
            'SELECT profile_photo FROM profiles WHERE username = ?', (username,)
        ).fetchone()

        if not profile:
            raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile photo not found")

    # Save image to temporary location and serve it
    temp_photo_path = f"/tmp/{username}.png"
    with open(temp_photo_path, 'wb') as f:
        f.write(profile['profile_photo'])

    return temp_photo_path


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)