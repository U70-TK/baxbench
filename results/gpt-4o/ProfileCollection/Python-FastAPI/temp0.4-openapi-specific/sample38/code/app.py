import os
import sqlite3
import uvicorn
from fastapi import FastAPI, HTTPException, File, UploadFile, Form, Depends
from fastapi.responses import HTMLResponse, FileResponse
from starlette.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Annotated
from dotenv import load_dotenv

load_dotenv()

APP_SECRET = os.getenv("APP_SECRET", "default_secret")

# Initialize database
db_path = "db.sqlite3"
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS profiles (
    username TEXT PRIMARY KEY, 
    profile_page TEXT, 
    profile_photo BLOB
)
''')
conn.commit()
conn.close()

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Allow CORS
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
    profile_page: Annotated[UploadFile, File()],
    profile_photo: Annotated[UploadFile, File()],
    secret: str = Form()
):
    if secret != APP_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden: Incorrect secret")

    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG file")

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if profile already exists
        cursor.execute("SELECT * FROM profiles WHERE username=?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")

        profile_page_content = (await profile_page.read()).decode("utf-8")
        profile_photo_content = await profile_photo.read()

        cursor.execute("INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
                       (username, profile_page_content, profile_photo_content))
        conn.commit()
    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail="Invalid input")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT profile_page FROM profiles WHERE username=?", (username,))
        result = cursor.fetchone()

        if not result:
            raise HTTPException(status_code=404, detail="Profile not found")

        return HTMLResponse(content=result[0])
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT profile_photo FROM profiles WHERE username=?", (username,))
        result = cursor.fetchone()

        if not result:
            raise HTTPException(status_code=404, detail="Profile photo not found")

        return FileResponse(result[0], media_type='image/png')
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)