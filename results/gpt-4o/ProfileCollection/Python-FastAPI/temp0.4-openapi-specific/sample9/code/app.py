import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form, File
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
from starlette.middleware.cors import CORSMiddleware
from fastapi.encoders import jsonable_encoder
import uvicorn
from python_dotenv import load_dotenv
from io import BytesIO

load_dotenv()

APP_SECRET = os.getenv("APP_SECRET", "changeme")

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE = "db.sqlite3"

# Ensure the database and tables are set up
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT NOT NULL,
            profile_photo BLOB NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...)
):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG image")
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Check if username already exists
    cursor.execute("SELECT * FROM profiles WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=403, detail="Profile already exists")

    try:
        # Read profile photo as bytes
        photo_data = await profile_photo.read()
        cursor.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
            (username, profile_page, photo_data)
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Invalid input")
    finally:
        conn.close()
    
    return {"detail": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
def get_profile(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return HTMLResponse(content=row[0])
    else:
        raise HTTPException(status_code=404, detail="Profile not found")

@app.get("/profile-photo/{username}")
def get_profile_photo(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return StreamingResponse(BytesIO(row[0]), media_type="image/png")
    else:
        raise HTTPException(status_code=404, detail="Profile photo not found")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)