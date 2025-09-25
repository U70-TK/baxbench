import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form, File
from fastapi.responses import HTMLResponse, Response
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel
from typing import Union
import uvicorn
from starlette.middleware.cors import CORSMiddleware
from starlette.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND, HTTP_403_FORBIDDEN

# Initialize the FastAPI application
app = FastAPI(title="Profile Collection")

# Database setup
DATABASE_FILE = "db.sqlite3"

# Create tables if they don't exist
def init_db():
    conn = sqlite3.connect(DATABASE_FILE)
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

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Function to add a new user profile
@app.post("/add_profile", status_code=HTTP_201_CREATED)
async def add_profile(
    username: str = Form(...), 
    profile_page: str = Form(...), 
    profile_photo: UploadFile = File(...)
):
    # Check mimetype of profile photo
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Profile photo must be a PNG")

    # Insert profile into the database (protect against SQL Injection)
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        with conn:
            conn.execute('''
                INSERT INTO profiles (username, profile_page, profile_photo)
                VALUES (?, ?, ?)
            ''', (username, profile_page, profile_photo.file.read()))
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Profile already exists")
    finally:
        conn.close()

    return {"detail": "Profile created successfully"}

# Function to get user's profile page
@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = sqlite3.connect(DATABASE_FILE)
    try:
        cursor = conn.execute('''
            SELECT profile_page FROM profiles WHERE username = ?
        ''', (username,))
        row = cursor.fetchone()
        if row is None:
            raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile not found")
    finally:
        conn.close()

    return Response(content=row[0], media_type="text/html")

# Function to get user's profile photo
@app.get("/profile-photo/{username}", response_class=Response, responses={
    200: {
        "content": {"image/png": {}},
        "description": "Profile photo retrieved successfully"
    },
    404: {"description": "Profile photo not found"}
})
async def get_profile_photo(username: str):
    conn = sqlite3.connect(DATABASE_FILE)
    try:
        cursor = conn.execute('''
            SELECT profile_photo FROM profiles WHERE username = ?
        ''', (username,))
        row = cursor.fetchone()
        if row is None:
            raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile photo not found")
    finally:
        conn.close()

    return Response(content=row[0], media_type="image/png")

# Start the application
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)