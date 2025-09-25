import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import Response
from typing import Union
import uvicorn

# Setup FastAPI
app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Define the database connection and create tables
def get_db_connection():
    conn = sqlite3.connect('db.sqlite3')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    try:
        with conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS profiles (
                    username TEXT PRIMARY KEY,
                    profile_page TEXT,
                    profile_photo BLOB
                )
            ''')
    except sqlite3.Error as e:
        print(f"Database error occurred: {e}")
    finally:
        conn.close()

init_db()

# Endpoint to add a new profile
@app.post("/add_profile", status_code=201)
async def add_profile(username: str = Form(...), profile_page: str = Form(...), profile_photo: UploadFile = File(...)):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG file")
    
    conn = get_db_connection()
    try:
        with conn:
            cursor = conn.execute("SELECT * FROM profiles WHERE username = ?", (username,))
            existing_profile = cursor.fetchone()
            if existing_profile:
                raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")
        
            photo_bytes = await profile_photo.read()
            conn.execute(
                "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
                (username, profile_page, photo_bytes)
            )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Invalid input or username already exists")
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error occurred: {e}")
    finally:
        conn.close()
    
    return Response(status_code=201)

# Endpoint to get the profile HTML content
@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = get_db_connection()
    try:
        cursor = conn.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
        profile = cursor.fetchone()
        if not profile:
            raise HTTPException(status_code=404, detail="Profile not found")
        return HTMLResponse(content=profile["profile_page"])
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error occurred: {e}")
    finally:
        conn.close()

# Endpoint to get the profile photo PNG
@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    conn = get_db_connection()
    try:
        cursor = conn.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
        profile = cursor.fetchone()
        if not profile:
            raise HTTPException(status_code=404, detail="Profile photo not found")
        
        with open(f"/tmp/{username}.png", "wb") as f:
            f.write(profile["profile_photo"])

        return FileResponse(f"/tmp/{username}.png", media_type="image/png")
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error occurred: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)