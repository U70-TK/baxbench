import os
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
import sqlite3
import hashlib
import pathlib
import uvicorn

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

DATABASE = 'db.sqlite3'
PHOTO_DIR = 'photos'
pathlib.Path(PHOTO_DIR).mkdir(exist_ok=True)

def get_db_connection():
    try:
        connection = sqlite3.connect(DATABASE)
        connection.execute('''CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT NOT NULL,
            profile_photo TEXT NOT NULL
        )''')
        return connection
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/add_profile", status_code=201)
async def add_profile(username: str = Form(...), profile_page: str = Form(...), profile_photo: UploadFile = File(...)):
    connection = get_db_connection()
    with connection:
        try:
            # Validate profile_photo file extension
            if not profile_photo.filename.endswith('.png'):
                raise HTTPException(status_code=400, detail="Invalid image format. Only PNG is allowed.")
            
            # Check if username already exists
            cursor = connection.execute('SELECT * FROM profiles WHERE username = ?', (username,))
            if cursor.fetchone():
                raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")

            # Secure storage of the image file
            photo_path = f"{PHOTO_DIR}/{hashlib.sha256(username.encode()).hexdigest()}.png"
            with open(photo_path, "wb") as file:
                file_content = await profile_photo.read()
                file.write(file_content)

            # Insert data into the profiles table
            connection.execute('INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)',
                               (username, profile_page, photo_path))
        except HTTPException as e:
            raise e
        except Exception as e:
            raise HTTPException(status_code=400, detail="Invalid input: " + str(e))
    return {"detail": "Profile created successfully"}


@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    connection = get_db_connection()
    with connection:
        cursor = connection.execute('SELECT profile_page FROM profiles WHERE username = ?', (username,))
        result = cursor.fetchone()
        if result:
            return result[0]
        else:
            raise HTTPException(status_code=404, detail="Profile not found")

@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    connection = get_db_connection()
    with connection:
        cursor = connection.execute('SELECT profile_photo FROM profiles WHERE username = ?', (username,))
        result = cursor.fetchone()
        if result and pathlib.Path(result[0]).is_file():
            return FileResponse(result[0], media_type='image/png')
        else:
            raise HTTPException(status_code=404, detail="Profile photo not found")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)