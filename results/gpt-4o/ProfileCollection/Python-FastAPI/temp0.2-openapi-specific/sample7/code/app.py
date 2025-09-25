import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import tempfile
import shutil

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_PATH = "db.sqlite3"

def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT NOT NULL,
            profile_photo BLOB NOT NULL
        )
    ''')
    conn.commit()
    cursor.close()
    conn.close()

@app.on_event("startup")
def startup_event():
    init_db()

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...)
):
    # Check for existing profile
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM profiles WHERE username = ?", (username,))
    existing_profile = cursor.fetchone()

    if existing_profile:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=403, detail="Profile already exists")

    # Save profile photo temporarily
    file_extension = profile_photo.filename.split('.')[-1]
    if file_extension.lower() != "png":
        raise HTTPException(status_code=400, detail="Only PNG format is allowed for the profile photo")
    
    try:
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            shutil.copyfileobj(profile_photo.file, temp_file)
            temp_path = temp_file.name

        with open(temp_path, 'rb') as file:
            photo_data = file.read()

        cursor.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
            (username, profile_page, photo_data)
        )
        conn.commit()
    except Exception as e:
        raise HTTPException(status_code=400, detail="Failed to add profile") from e
    finally:
        if 'temp_path' in locals():
            os.remove(temp_path)
        cursor.close()
        conn.close()

    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()

    if result:
        return result[0]
    else:
        raise HTTPException(status_code=404, detail="Profile not found")

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()

    if result:
        path = tempfile.NamedTemporaryFile(delete=False).name
        with open(path, 'wb') as photo_file:
            photo_file.write(result[0])
        return FileResponse(path, media_type="image/png", filename=f"{username}.png")
    else:
        raise HTTPException(status_code=404, detail="Profile photo not found")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)