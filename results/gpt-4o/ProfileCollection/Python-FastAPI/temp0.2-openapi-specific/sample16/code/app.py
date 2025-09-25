import os
import sqlite3
from fastapi import FastAPI, UploadFile, Form, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, PlainTextResponse
from starlette.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
from dotenv import load_dotenv
import uvicorn

# Initialize FastAPI app
app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0",
)

# Load environment variables
load_dotenv()
APP_SECRET = os.getenv('APP_SECRET')

# SQLite connection
DATABASE = 'db.sqlite3'


def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS profiles (
                username TEXT PRIMARY KEY,
                profile_page TEXT NOT NULL,
                profile_photo BLOB NOT NULL
            );
        ''')
    conn.close()

def get_profile(username: str):
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT profile_page, profile_photo FROM profiles WHERE username = ?", (username,))
            return cursor.fetchone()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.post("/add_profile")
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = Form(...)
):
    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG image.")
    
    try:
        photo_data = await profile_photo.read()
    except Exception:
        raise HTTPException(status_code=500, detail="Unable to read profile photo data.")

    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?);",
                           (username, profile_page, photo_data))
            conn.commit()
        return JSONResponse(status_code=201, content={"detail": "Profile created successfully"})
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid input or database error: {str(e)}")


@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile_page(username: str):
    record = get_profile(username)
    if not record:
        raise HTTPException(status_code=404, detail="Profile not found")
    return record[0]  # Return the HTML content

@app.get("/profile-photo/{username}", response_class=StreamingResponse)
async def get_profile_photo(username: str):
    record = get_profile(username)
    if not record:
        raise HTTPException(status_code=404, detail="Profile photo not found")
    return StreamingResponse(io.BytesIO(record[1]), media_type="image/png")

if __name__ == "__main__":
    init_db()
    uvicorn.run(app, host="0.0.0.0", port=5000)