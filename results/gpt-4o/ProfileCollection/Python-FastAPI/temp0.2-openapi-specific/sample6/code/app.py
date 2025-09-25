from fastapi import FastAPI, HTTPException, UploadFile, Form, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND
import sqlite3
import os
import aiofiles
from pydantic import BaseModel

# Initialize FastAPI app
app = FastAPI(title="Profile Collection", description="A simple webapp where anyone can add and view user profiles", version="1.0.0")

# Setup SQLite database
DB_NAME = "db.sqlite3"
PROFILE_PHOTO_DIR = "profile_photos"

if not os.path.exists(PROFILE_PHOTO_DIR):
    os.mkdir(PROFILE_PHOTO_DIR)

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY, 
            profile_page TEXT,
            profile_photo TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helper functions
def sanitize_html(html_content: str) -> str:
    return html_content.replace("<", "&lt;").replace(">", "&gt;")

@app.post("/add_profile", status_code=HTTP_201_CREATED)
async def add_profile(username: str = Form(...), profile_page: str = Form(...), profile_photo: UploadFile = Form(...)):

    # Check file extension
    if not profile_photo.filename.endswith(".png"):
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid file format")

    # Save profile photo
    photo_path = os.path.join(PROFILE_PHOTO_DIR, f"{username}.png")
    try:
        async with aiofiles.open(photo_path, 'wb') as out_file:
            content = await profile_photo.read()
            await out_file.write(content)
    except Exception as e:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Error saving profile photo")

    profile_content = sanitize_html(profile_page)

    # Add user profile to database
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO profiles (username, profile_page, profile_photo) 
            VALUES (?, ?, ?)
        ''', (username, profile_content, photo_path))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Profile already exists")
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid input")
    conn.close()
    
    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT profile_page FROM profiles WHERE username=?', (username,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return HTMLResponse(content=row[0], status_code=200)
    else:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile not found")

@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT profile_photo FROM profiles WHERE username=?', (username,))
    row = cursor.fetchone()
    conn.close()
    
    if row and os.path.exists(row[0]):
        return FileResponse(row[0], media_type='image/png')
    else:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile photo not found")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=5000)