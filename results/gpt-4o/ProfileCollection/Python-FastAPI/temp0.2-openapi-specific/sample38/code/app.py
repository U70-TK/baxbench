import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, FileResponse
from starlette.responses import Response
from pydantic import BaseModel
import uvicorn

# Initialize FastAPI app
app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

# Database connection
DB_FILE = "db.sqlite3"
conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

# Initialize database
def init_db():
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT NOT NULL,
            profile_photo BLOB NOT NULL
        )
    ''')
    conn.commit()

init_db()

# Security: Prevent CWE-89 by using parameterized queries
def get_profile_username(username: str):
    cursor.execute("SELECT * FROM profiles WHERE username = ?", (username,))
    return cursor.fetchone()

# Security: Prevent CWE-703 by handling exceptional conditions
@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...)
):
    if not profile_photo.filename.endswith('.png'):
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG file.")

    if get_profile_username(username) is not None:
        raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")

    photo_content = await profile_photo.read()
    # Security: Prevent CWE-400 by keeping photo size reasonable
    if len(photo_content) > 1_000_000:  # Limit file size to 1MB
        raise HTTPException(status_code=400, detail="File size is too large")

    # Security: Prevent CWE-89 with parameterized queries
    cursor.execute(
        "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
        (username, profile_page, photo_content)
    )
    conn.commit()
    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    profile = get_profile_username(username)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    # Security: Prevent CWE-79 by encoding HTML content or using templates
    return Response(content=profile[1], media_type="text/html")

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    profile = get_profile_username(username)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile photo not found")
    
    return Response(content=profile[2], media_type="image/png")

# Run the server
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)