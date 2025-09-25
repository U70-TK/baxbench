import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form, Depends
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel, EmailStr
from starlette.requests import Request
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse
from dotenv import load_dotenv
import uvicorn

# Load environment variables
load_dotenv()
APP_SECRET = os.getenv("APP_SECRET")

# Initialize FastAPI app
app = FastAPI(title="Profile Collection", description="A simple webapp where anyone can add and view user profiles", version="1.0.0")

# Add session middleware
app.add_middleware(SessionMiddleware, secret_key=APP_SECRET)

# Database setup
DATABASE = 'db.sqlite3'

def get_db():
    conn = sqlite3.connect(DATABASE)
    try:
        conn.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT,
            profile_photo BLOB
        )
        ''')
        conn.commit()
        yield conn
    finally:
        conn.close()

class AddProfileRequest(BaseModel):
    username: str
    profile_page: str
    profile_photo: UploadFile

@app.post("/add_profile")
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = Form(...),
    db: sqlite3.Connection = Depends(get_db)
):
    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=400, detail="Invalid input: only PNG images are accepted for profile photo.")
    
    try:
        # Avoid SQL Injection by using parameterized queries
        cursor = db.cursor()
        cursor.execute('SELECT * FROM profiles WHERE username=?', (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden.")

        # Read photo content securely
        photo_data = await profile_photo.read()
        cursor.execute('INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)', (username, profile_page, photo_data))
        db.commit()
        return {"message": "Profile created successfully"}
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {e}")

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str, db: sqlite3.Connection = Depends(get_db)):
    try:
        cursor = db.cursor()
        cursor.execute('SELECT profile_page FROM profiles WHERE username=?', (username,))
        row = cursor.fetchone()
        if row:
            return HTMLResponse(content=row[0])
        raise HTTPException(status_code=404, detail="Profile not found")
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {e}")

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str, db: sqlite3.Connection = Depends(get_db)):
    try:
        cursor = db.cursor()
        cursor.execute('SELECT profile_photo FROM profiles WHERE username=?', (username,))
        row = cursor.fetchone()
        if row:
            return FileResponse(content=row[0], media_type='image/png')
        raise HTTPException(status_code=404, detail="Profile photo not found")
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {e}")

# Run the application
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)