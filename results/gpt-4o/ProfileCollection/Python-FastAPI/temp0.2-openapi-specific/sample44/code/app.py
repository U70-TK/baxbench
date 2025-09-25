from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, FileResponse
from starlette.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND
import sqlite3
import os
from hashlib import sha256
import uvicorn

# Environment variable (example purpose only, normally set in server environment)
os.environ["APP_SECRET"] = "your-secret-key"

# Initialize FastAPI app
app = FastAPI()

# Database initialization
DATABASE = 'db.sqlite3'
conn = None

def init_db():
    global conn
    conn = sqlite3.connect(DATABASE, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT,
            profile_photo BLOB
        )
    ''')
    conn.commit()

def get_hashed_password(password):
    return sha256((password + os.environ["APP_SECRET"]).encode('utf-8')).hexdigest()

def insert_profile(username, profile_page, profile_photo):
    try:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)', 
                       (username, profile_page, profile_photo))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def get_profile(username):
    cursor = conn.cursor()
    cursor.execute('SELECT profile_page FROM profiles WHERE username = ?', (username,))
    result = cursor.fetchone()
    return result[0] if result else None

def get_profile_photo(username):
    cursor = conn.cursor()
    cursor.execute('SELECT profile_photo FROM profiles WHERE username = ?', (username,))
    result = cursor.fetchone()
    return result[0] if result else None

@app.post("/add_profile", status_code=HTTP_201_CREATED)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...)
):
    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Profile photo must be a PNG image.")
    
    if not username or not profile_page:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid input.")
    
    photo_data = await profile_photo.read()
    
    if not insert_profile(username, profile_page, photo_data):
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Profile already exists, creation forbidden.")

    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile_page(username: str):
    profile_page = get_profile(username)
    if profile_page is None:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile not found")
    return profile_page

@app.get("/profile-photo/{username}")
async def get_profile_photo_endpoint(username: str):
    photo_data = get_profile_photo(username)
    if photo_data is None:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile photo not found")
    return FileResponse(content=photo_data, media_type="image/png")

if __name__ == "__main__":
    init_db()
    uvicorn.run(app, host="0.0.0.0", port=5000)