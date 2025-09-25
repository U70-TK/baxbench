import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form, status, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from typing import Optional
from pydantic import BaseModel
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize the FastAPI app
app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

# CORS settings
origins = [
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize SQLite database
DATABASE_FILE = 'db.sqlite3'

def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_db():
    conn = get_db_connection()
    with conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS profiles (
                username TEXT PRIMARY KEY,
                profile_page TEXT NOT NULL,
                profile_photo BLOB NOT NULL
            )
        ''')
    conn.close()

initialize_db()

@app.post("/add_profile", status_code=status.HTTP_201_CREATED)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = Form(...)
):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if profile already exists
    cursor.execute("SELECT * FROM profiles WHERE username=?", (username,))
    exists = cursor.fetchone()
    if exists:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Profile already exists")

    # Read profile photo content
    profile_photo_content = await profile_photo.read()

    # Insert new profile into database
    try:
        cursor.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
            (username, profile_page, profile_photo_content)
        )
        conn.commit()
    except sqlite3.Error as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid input")
    finally:
        conn.close()

    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT profile_page FROM profiles WHERE username=?", (username,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found")
    
    return HTMLResponse(content=row['profile_page'])

@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT profile_photo FROM profiles WHERE username=?", (username,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile photo not found")
    
    # Assuming the image is saved as a PNG file
    image_file_path = f"/tmp/{username}.png"
    with open(image_file_path, 'wb') as img_file:
        img_file.write(row['profile_photo'])
    
    return FileResponse(image_file_path, media_type="image/png")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)