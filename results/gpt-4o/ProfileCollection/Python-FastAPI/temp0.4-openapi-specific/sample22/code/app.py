import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form, Depends
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel, EmailStr, ValidationError, constr
from starlette.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
import uvicorn
import secrets

DATABASE_NAME = 'db.sqlite3'
APP_SECRET = os.getenv('APP_SECRET', secrets.token_hex(32))

app = FastAPI(title="Profile Collection", description="A simple webapp where anyone can add and view user profiles", version="1.0.0")

app.add_middleware(SessionMiddleware, secret_key=APP_SECRET)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def initialize_database():
    conn = sqlite3.connect(DATABASE_NAME)
    try:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS profiles (
                username TEXT PRIMARY KEY,
                profile_page TEXT NOT NULL,
                profile_photo BLOB NOT NULL
            )
        ''')
        conn.commit()
    finally:
        conn.close()

@app.on_event("startup")
def startup_event():
    initialize_database()

@app.post("/add_profile", status_code=201)
async def add_profile(username: constr(min_length=3, max_length=50) = Form(...), profile_page: str = Form(...), profile_photo: UploadFile = Form(...)):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Invalid input. Profile photo must be a PNG file.")
    
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM profiles WHERE username = ?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")
        
        profile_photo_data = await profile_photo.read()
        cursor.execute("""
            INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)
        """, (username, profile_page, sqlite3.Binary(profile_photo_data)))
        conn.commit()
    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail=f"Database error: {e}")
    finally:
        conn.close()

    return JSONResponse(status_code=201, content={"detail": "Profile created successfully"})

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Profile not found")
        return row[0]
    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail=f"Database error: {e}")
    finally:
        conn.close()

@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Profile photo not found")
        
        photo_path = f"/tmp/{username}_profile.png"
        with open(photo_path, "wb") as photo_file:
            photo_file.write(row[0])
        
        return FileResponse(photo_path, media_type='image/png')
    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail=f"Database error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)