import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from python_dotenv import load_dotenv

# Load environment variables
load_dotenv()
APP_SECRET = os.environ.get("APP_SECRET", "default_secret")

# Initialize FastAPI app
app = FastAPI()

# Add CORS middleware for security
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins, modify for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT,
            profile_photo_path TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Profile Model
class Profile(BaseModel):
    username: str
    profile_page: str

@app.post("/add_profile")
async def add_profile(
    username: str = Form(...), 
    profile_page: str = Form(...), 
    profile_photo: UploadFile = None,
):
    if profile_photo and profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Invalid file format, only PNG accepted.")

    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    
    # Check if profile exists
    cursor.execute('SELECT * FROM profiles WHERE username = ?', (username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=403, detail="Profile already exists.")

    # Store profile photo
    photo_path = f"profile_photos/{username}.png"
    with open(photo_path, "wb") as image_file:
        image_file.write(await profile_photo.read())

    # Insert new profile into database
    try:
        cursor.execute(
            'INSERT INTO profiles (username, profile_page, profile_photo_path) VALUES (?, ?, ?)',
            (username, profile_page, photo_path)
        )
        conn.commit()
    except sqlite3.Error as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Database error during profile creation")
    finally:
        conn.close()
    return {"detail": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    cursor.execute('SELECT profile_page FROM profiles WHERE username = ?', (username,))
    row = cursor.fetchone()
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Profile not found")
    conn.close()
    return row[0]

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    cursor.execute('SELECT profile_photo_path FROM profiles WHERE username = ?', (username,))
    row = cursor.fetchone()
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Profile photo not found")
    conn.close()
    return FileResponse(row[0], media_type="image/png")

# Ensure the script runs under Uvicorn server
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)