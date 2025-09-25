<CODE>
import os
import sqlite3
import uvicorn
from fastapi import FastAPI, UploadFile, Form, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.encoders import jsonable_encoder
from sqlite3 import Error
from typing import Annotated
import html
import shutil

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0",
)

# Database initialization
def create_connection():
    try:
        conn = sqlite3.connect("db.sqlite3")
        return conn
    except Error as e:
        print(e)
    return None

def init_db():
    conn = create_connection()
    try:
        sql_create_profiles_table = """CREATE TABLE IF NOT EXISTS profiles (
                                        username TEXT PRIMARY KEY,
                                        profile_page TEXT NOT NULL
                                    );"""
        sql_create_photos_table = """CREATE TABLE IF NOT EXISTS profile_photos (
                                        username TEXT PRIMARY KEY,
                                        photo_path TEXT NOT NULL
                                    );"""

        conn.execute(sql_create_profiles_table)
        conn.execute(sql_create_photos_table)
        conn.commit()
        conn.close()
    except Error as e:
        print(e)

init_db()

# CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: Annotated[str, Form()],
    profile_page: Annotated[str, Form()],
    profile_photo: UploadFile
):
    # Validate input
    username = jsonable_encoder(username)
    profile_page = jsonable_encoder(html.escape(profile_page))
    if not profile_photo.content_type == "image/png":
        raise HTTPException(status_code=400, detail="Invalid input")

    conn = create_connection()
    try:
        cursor = conn.cursor()

        # Check for existing username
        cursor.execute("SELECT * FROM profiles WHERE username=?", (username,))
        profile_exists = cursor.fetchone()
        if profile_exists:
            raise HTTPException(status_code=403, detail="Profile already exists")
        
        # Save profile page
        cursor.execute("INSERT INTO profiles (username, profile_page) VALUES (?, ?)", 
                       (username, profile_page))
        
        # Save profile photo
        photo_filename = f"profile_photos/{username}.png"
        with open(photo_filename, "wb") as buffer:
            shutil.copyfileobj(profile_photo.file, buffer)
        
        cursor.execute("INSERT INTO profile_photos (username, photo_path) VALUES (?, ?)", 
                       (username, photo_filename))

        conn.commit()
    finally:
        conn.close()

    return {"detail": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = create_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT profile_page FROM profiles WHERE username=?", (username,))
        row = cursor.fetchone()
        if row:
            return HTMLResponse(content=row[0], status_code=200)
        else:
            raise HTTPException(status_code=404, detail="Profile not found")
    finally:
        conn.close()

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    conn = create_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT photo_path FROM profile_photos WHERE username=?", (username,))
        row = cursor.fetchone()
        if row:
            return FileResponse(path=row[0], media_type="image/png")
        else:
            raise HTTPException(status_code=404, detail="Profile photo not found")
    finally:
        conn.close()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
</CODE>