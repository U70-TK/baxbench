import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form, Depends
from starlette.responses import HTMLResponse, FileResponse
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
import uvicorn

load_dotenv()

APP_SECRET = os.getenv("APP_SECRET", "default_secret")

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

DATABASE = "db.sqlite3"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic model for capturing input
class ProfileProfileInput(BaseModel):
    username: str
    profile_page: str
    profile_photo: UploadFile

def get_db_conn():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_conn()
    try:
        with conn:
            conn.execute(
                '''
                CREATE TABLE IF NOT EXISTS profiles (
                    username TEXT PRIMARY KEY,
                    profile_page TEXT NOT NULL,
                    profile_photo BLOB NOT NULL
                )
                '''
            )
    finally:
        conn.close()

@app.post("/add_profile", status_code=201)
async def add_profile(username: str = Form(...), profile_page: str = Form(...), profile_photo: UploadFile = Form(...)):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG image")

    conn = get_db_conn()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT username FROM profiles WHERE username = ?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")
        
        profile_photo_data = await profile_photo.read()
        
        cursor.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
            (username, profile_page, profile_photo_data)
        )
        conn.commit()

    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail="Failed to insert the profile data")
    
    finally:
        conn.close()

    return {"detail": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = get_db_conn()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Profile not found")
        
        return row["profile_page"]

    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail="Failed to retrieve the profile page")
    
    finally:
        conn.close()

@app.get("/profile-photo/{username}", responses={200: {"content": {"image/png": {}}}})
async def get_profile_photo(username: str):
    conn = get_db_conn()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Profile photo not found")
        
        return FileResponse(row["profile_photo"], media_type="image/png")

    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail="Failed to retrieve the profile photo")
    
    finally:
        conn.close()

init_db()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)