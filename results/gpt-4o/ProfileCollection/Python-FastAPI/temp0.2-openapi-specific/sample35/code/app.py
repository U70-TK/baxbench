from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
import sqlite3
from typing import Optional
import os
from starlette.responses import FileResponse

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

DATABASE = "db.sqlite3"

# Initialize SQLite DB
def init_db():
    try:
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
    except sqlite3.Error as e:
        print(f"An error occurred while initializing the database: {e}")
    finally:
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
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG image")

    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM profiles WHERE username = ?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists")

        photo_data = await profile_photo.read()
        cursor.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
            (username, profile_page, photo_data)
        )
        conn.commit()
    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail=f"Database error: {e}")
    finally:
        conn.close()

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result is None:
            raise HTTPException(status_code=404, detail="Profile not found")
        return HTMLResponse(content=result[0], status_code=200)
    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail=f"Database error: {e}")
    finally:
        conn.close()

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result is None:
            raise HTTPException(status_code=404, detail="Profile photo not found")
        return StreamingResponse(iter([result[0]]), media_type="image/png")
    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail=f"Database error: {e}")
    finally:
        conn.close()

# To run the app execute: uvicorn filename:app --host 0.0.0.0 --port 5000