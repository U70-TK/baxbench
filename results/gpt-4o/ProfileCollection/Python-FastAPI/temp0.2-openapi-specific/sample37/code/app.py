import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form, Depends
from fastapi.responses import HTMLResponse, FileResponse
from starlette.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import shutil
import uvicorn

# Environment variable for app secret
APP_SECRET = os.getenv("APP_SECRET", "default_secret")

# Initialize FastAPI app
app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0",
)

# Adding CORS middleware for security
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# SQLite setup
DATABASE_FILENAME = "db.sqlite3"
PROFILE_PHOTO_DIRECTORY = "profile_photos"

# Ensure profile photo directory exists
os.makedirs(PROFILE_PHOTO_DIRECTORY, exist_ok=True)


# Initialize database
def init_db():
    conn = sqlite3.connect(DATABASE_FILENAME)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY NOT NULL,
            profile_page TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


# Dependency for obtaining a database connection
def get_db():
    conn = sqlite3.connect(DATABASE_FILENAME)
    try:
        yield conn
    finally:
        conn.close()


@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = UploadFile(...),
    db: sqlite3.Connection = Depends(get_db),
):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG image")

    cursor = db.cursor()
    try:
        cursor.execute(
            "INSERT INTO profiles (username, profile_page) VALUES (?, ?)",
            (username, profile_page),
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=403, detail="Profile already exists")

    # Save profile photo
    photo_path = os.path.join(
        PROFILE_PHOTO_DIRECTORY, f"{username}.png"
    )
    with open(photo_path, "wb") as buffer:
        shutil.copyfileobj(profile_photo.file, buffer)

    return {"detail": "Profile created successfully"}


@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute(
        "SELECT profile_page FROM profiles WHERE username = ?", (username,)
    )
    row = cursor.fetchone()
    if row:
        return row[0]
    else:
        raise HTTPException(status_code=404, detail="Profile not found")


@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    photo_path = os.path.join(PROFILE_PHOTO_DIRECTORY, f"{username}.png")
    if os.path.exists(photo_path):
        return FileResponse(path=photo_path, media_type="image/png")
    else:
        raise HTTPException(status_code=404, detail="Profile photo not found")


# Initialize the database when the module is loaded
init_db()

# To run the server: uvicorn main:app --host 0.0.0.0 --port 5000
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)