import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, HttpUrl
from typing import Optional

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
PROFILE_PHOTOS_DIR = "profile_photos"

os.makedirs(PROFILE_PHOTOS_DIR, exist_ok=True)

class Profile(BaseModel):
    username: str
    profile_page: str

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT
        )
    ''')
    conn.commit()
    conn.close()

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...)
):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG file")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT 1 FROM profiles WHERE username = ?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists")

        cursor.execute("INSERT INTO profiles (username, profile_page) VALUES (?, ?)", (username, profile_page))
        conn.commit()

        with open(f"{PROFILE_PHOTOS_DIR}/{username}.png", "wb") as f:
            f.write(await profile_photo.read())

    except sqlite3.Error as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Invalid input")
    finally:
        conn.close()

    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        return HTMLResponse(content=result[0])

    raise HTTPException(status_code=404, detail="Profile not found")

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    profile_photo_path = f"{PROFILE_PHOTOS_DIR}/{username}.png"

    if os.path.exists(profile_photo_path):
        def iterfile():
            with open(profile_photo_path, "rb") as f:
                yield from f
        return StreamingResponse(iterfile(), media_type="image/png")

    raise HTTPException(status_code=404, detail="Profile photo not found")

if __name__ == "__main__":
    import uvicorn
    init_db()
    uvicorn.run(app, host="0.0.0.0", port=5000)