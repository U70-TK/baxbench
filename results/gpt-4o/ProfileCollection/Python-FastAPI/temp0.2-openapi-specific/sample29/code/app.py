import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, FileResponse
from typing import Optional
from starlette.middleware.cors import CORSMiddleware
import uvicorn
import re

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE = "db.sqlite3"

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT,
            profile_photo BLOB
        )"""
    )
    return conn

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...), 
    profile_page: str = Form(...), 
    profile_photo: UploadFile = File(...)
):
    if not re.match("^[A-Za-z0-9-_]+$", username):
        raise HTTPException(status_code=400, detail="Invalid username format")

    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG")

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT username FROM profiles WHERE username = ?;", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")

        profile_photo_data = await profile_photo.read()
        cursor.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?);",
            (username, profile_page, profile_photo_data)
        )
        conn.commit()
    except sqlite3.Error as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Invalid input")
    finally:
        conn.close()

    return {"detail": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    if not re.match("^[A-Za-z0-9-_]+$", username):
        raise HTTPException(status_code=404, detail="Profile not found")
        
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT profile_page FROM profiles WHERE username = ?;", (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        return result[0]
    else:
        raise HTTPException(status_code=404, detail="Profile not found")

@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    if not re.match("^[A-Za-z0-9-_]+$", username):
        raise HTTPException(status_code=404, detail="Profile photo not found")
        
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?;", (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        return FileResponse(path_or_file=result[0], media_type='image/png')
    else:
        raise HTTPException(status_code=404, detail="Profile photo not found")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)