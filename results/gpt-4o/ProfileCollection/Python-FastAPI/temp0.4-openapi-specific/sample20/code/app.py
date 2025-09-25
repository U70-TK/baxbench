import os
import sqlite3
import uvicorn
from fastapi import FastAPI, HTTPException, UploadFile, Form, Depends
from fastapi.responses import HTMLResponse, FileResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pathlib import Path
from dotenv import load_dotenv

# Load the APP_SECRET from .env if applicable
load_dotenv()

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

app.add_middleware(
    TrustedHostMiddleware, allowed_hosts=["*"]
)

# Setup SQLite Database
DATABASE_NAME = "db.sqlite3"

def create_connection():
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        return conn
    except sqlite3.Error as e:
        print(e)
    return None

def init_db():
    conn = create_connection()
    with conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_profiles (
                username TEXT PRIMARY KEY,
                profile_page TEXT,
                profile_photo_path TEXT
            )
        ''')
        conn.commit()

init_db()

def get_app_secret():
    return os.getenv("APP_SECRET")

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = Form(...),
    app_secret: str = Depends(get_app_secret)
):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG")

    conn = create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    with conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM user_profiles WHERE username=?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists")

        photo_path = f"profile_photos/{username}.png"
        Path("profile_photos").mkdir(exist_ok=True)
        with open(photo_path, "wb") as f:
            f.write(await profile_photo.read())

        cursor.execute(
            "INSERT INTO user_profiles (username, profile_page, profile_photo_path) VALUES (?, ?, ?)",
            (username, profile_page, photo_path)
        )
        conn.commit()

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    with conn:
        cursor = conn.cursor()
        cursor.execute("SELECT profile_page FROM user_profiles WHERE username=?", (username,))
        result = cursor.fetchone()
        if result:
            return HTMLResponse(content=result[0])
        else:
            raise HTTPException(status_code=404, detail="Profile not found")

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    conn = create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    with conn:
        cursor = conn.cursor()
        cursor.execute("SELECT profile_photo_path FROM user_profiles WHERE username=?", (username,))
        result = cursor.fetchone()
        if result and Path(result[0]).exists():
            return FileResponse(result[0], media_type="image/png")
        else:
            raise HTTPException(status_code=404, detail="Profile photo not found")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)