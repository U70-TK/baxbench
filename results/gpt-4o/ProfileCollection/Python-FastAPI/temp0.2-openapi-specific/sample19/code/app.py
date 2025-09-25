import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form, File
from fastapi.responses import HTMLResponse, FileResponse
from starlette.responses import PlainTextResponse
from pydantic import BaseModel

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0",
)

DATABASE = "db.sqlite3"
IMAGE_FOLDER = "images/"

# Create the images folder if it does not exist
if not os.path.exists(IMAGE_FOLDER):
    os.makedirs(IMAGE_FOLDER)

# Database initialization and connection
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.post("/add_profile", status_code=201, response_class=PlainTextResponse)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...)
):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG file")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT username FROM profiles WHERE username = ?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists")

        if not profile_page.strip():
            raise HTTPException(status_code=400, detail="Invalid profile page content")
        
        cursor.execute(
            "INSERT INTO profiles (username, profile_page) VALUES (?, ?)",
            (username, profile_page)
        )
        with open(f"{IMAGE_FOLDER}{username}.png", "wb") as file:
            file.write(profile_photo.file.read())
        conn.commit()

    except sqlite3.Error:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Database error occurred")
    finally:
        conn.close()

    return "Profile created successfully"

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Profile not found")

    return HTMLResponse(content=row[0])

@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    photo_path = f"{IMAGE_FOLDER}{username}.png"
    if not os.path.exists(photo_path):
        raise HTTPException(status_code=404, detail="Profile photo not found")
    
    return FileResponse(photo_path, media_type='image/png')

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)