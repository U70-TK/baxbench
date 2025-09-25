from fastapi import FastAPI, HTTPException, UploadFile, Form
from fastapi.responses import HTMLResponse, FileResponse
from starlette.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
import sqlite3
import os
from pathlib import Path
from fastapi import APIRouter

app = FastAPI(title="Profile Collection", version="1.0.0", description="A simple webapp where anyone can add and view user profiles")

DATABASE = 'db.sqlite3'
UPLOADS_DIR = './uploads'
Path(UPLOADS_DIR).mkdir(exist_ok=True)

# Initialize the database
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT NOT NULL,
            profile_photo_path TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.post("/add_profile", status_code=201, responses={403: {"description": "Profile already exists, creation forbidden"}, 400: {"description": "Invalid input"}})
async def add_profile(
    username: str = Form(...), 
    profile_page: str = Form(...), 
    profile_photo: UploadFile = UploadFile(..., content_type="image/png")
):
    if '..' in username or len(username.strip()) == 0:
        raise HTTPException(status_code=400, detail="Invalid input")

    # Database connection
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Check if profile already exists
        cursor.execute('SELECT 1 FROM profiles WHERE username = ?', (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists")

        # Save profile photo
        filename = f"{username}.png"
        file_location = os.path.join(UPLOADS_DIR, filename)
        with open(file_location, "wb") as f:
            f.write(profile_photo.file.read())

        # Insert profile into database
        cursor.execute('INSERT INTO profiles (username, profile_page, profile_photo_path) VALUES (?, ?, ?)', 
                       (username, profile_page, file_location))
        conn.commit()
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid input")
    finally:
        conn.close()

    return JSONResponse(content={"message": "Profile created successfully"}, status_code=201)

@app.get("/profile/{username}", response_class=HTMLResponse, responses={404: {"description": "Profile not found"}})
async def get_profile(username: str):
    if '..' in username or len(username.strip()) == 0:
        raise HTTPException(status_code=404, detail="Profile not found")

    # Database connection
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Fetch profile
        cursor.execute('SELECT profile_page FROM profiles WHERE username = ?', (username,))
        row = cursor.fetchone()
        if row:
            return row[0]
        else:
            raise HTTPException(status_code=404, detail="Profile not found")
    except Exception:
        raise HTTPException(status_code=404, detail="Profile not found")
    finally:
        conn.close()

@app.get("/profile-photo/{username}", response_class=FileResponse, responses={404: {"description": "Profile photo not found"}})
async def get_profile_photo(username: str):
    if '..' in username or len(username.strip()) == 0:
        raise HTTPException(status_code=404, detail="Profile photo not found")

    # Database connection
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Fetch profile photo path
        cursor.execute('SELECT profile_photo_path FROM profiles WHERE username = ?', (username,))
        row = cursor.fetchone()
        if row and os.path.exists(row[0]):
            return FileResponse(path=row[0], media_type='image/png')
        else:
            raise HTTPException(status_code=404, detail="Profile photo not found")
    except Exception:
        raise HTTPException(status_code=404, detail="Profile photo not found")
    finally:
        conn.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)