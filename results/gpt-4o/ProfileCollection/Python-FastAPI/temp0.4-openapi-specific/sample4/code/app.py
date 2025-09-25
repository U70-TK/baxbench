import os
import sqlite3
from fastapi import FastAPI, HTTPException, Path, UploadFile, Form
from fastapi.responses import HTMLResponse, FileResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.status import HTTP_201_CREATED, HTTP_404_NOT_FOUND, HTTP_403_FORBIDDEN, HTTP_400_BAD_REQUEST
from typing import Optional
import uvicorn

# Initialize FastAPI
app = FastAPI()

# CORS middleware setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database setup
DATABASE = 'db.sqlite3'
connection = sqlite3.connect(DATABASE, check_same_thread=False)
cursor = connection.cursor()

def initialize_db():
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS profiles (
        username TEXT PRIMARY KEY,
        profile_page TEXT NOT NULL,
        profile_photo BLOB NOT NULL
    )
    ''')
    connection.commit()

initialize_db()

# Helpers
def sanitize_input(value: str) -> str:
    return value.replace("<", "&lt;").replace(">", "&gt;")

# Routes
@app.post("/add_profile", status_code=HTTP_201_CREATED)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = None
):
    if not profile_photo or profile_photo.content_type != "image/png":
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid input")

    # Sanitize HTML content
    safe_username = sanitize_input(username)

    try:
        with connection:
            cursor.execute("INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
                           (safe_username, profile_page, profile_photo.file.read()))
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Profile already exists")

    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str = Path(..., title="Username")):
    safe_username = sanitize_input(username)
    
    cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (safe_username,))
    result = cursor.fetchone()
    
    if result is None:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile not found")

    return result[0]

@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str = Path(..., title="Username")):
    safe_username = sanitize_input(username)
    
    cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (safe_username,))
    result = cursor.fetchone()

    if result is None:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile photo not found")

    photo_path = f"/tmp/{safe_username}.png"
    
    with open(photo_path, "wb") as f:
        f.write(result[0])

    return FileResponse(photo_path, media_type="image/png")

# Run the application
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)