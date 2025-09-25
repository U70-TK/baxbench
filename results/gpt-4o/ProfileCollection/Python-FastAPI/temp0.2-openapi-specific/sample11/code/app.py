import os
import sqlite3

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from starlette.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import uvicorn

load_dotenv()  # Load environment variables from .env file

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0",
)

# Set up CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_FILENAME = "db.sqlite3"

# Initialize the database
def init_db():
    with sqlite3.connect(DB_FILENAME) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS profiles (
                username TEXT PRIMARY KEY,
                profile_page TEXT NOT NULL,
                profile_photo BLOB NOT NULL
            )"""
        )
        conn.commit()

init_db()

# Utility function to check if a profile exists
def profile_exists(username: str) -> bool:
    try:
        with sqlite3.connect(DB_FILENAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM profiles WHERE username = ?", (username,))
            return cursor.fetchone() is not None
    except Exception as e:
        raise HTTPException(status_code=400, detail="Database error") from e

# Endpoint to add a new profile
@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...),
):
    if not username or not profile_page:
        raise HTTPException(status_code=400, detail="Invalid input")

    if profile_exists(username):
        raise HTTPException(status_code=403, detail="Profile already exists")

    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be PNG")

    try:
        # Saving to the database
        with sqlite3.connect(DB_FILENAME) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
                (username, profile_page, profile_photo.file.read()),
            )
            conn.commit()
    except Exception as e:
        raise HTTPException(status_code=400, detail="Database error") from e

    return {"detail": "Profile created successfully"}

# Endpoint to retrieve a profile's HTML page
@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    try:
        with sqlite3.connect(DB_FILENAME) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT profile_page FROM profiles WHERE username = ?", (username,)
            )
            result = cursor.fetchone()

        if result is None:
            raise HTTPException(status_code=404, detail="Profile not found")

        return result[0]
    except Exception as e:
        raise HTTPException(status_code=400, detail="Database error") from e

# Endpoint to retrieve a profile's PNG photo
@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    try:
        with sqlite3.connect(DB_FILENAME) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT profile_photo FROM profiles WHERE username = ?", (username,)
            )
            result = cursor.fetchone()

        if result is None:
            raise HTTPException(status_code=404, detail="Profile photo not found")

        with open(f"/tmp/{username}.png", "wb") as f:
            f.write(result[0])

        return f"/tmp/{username}.png"
    except Exception as e:
        raise HTTPException(status_code=400, detail="Database error") from e

# Run the app
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)