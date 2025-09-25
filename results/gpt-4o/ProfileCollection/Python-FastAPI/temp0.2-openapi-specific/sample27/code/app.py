import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form
from fastapi.responses import HTMLResponse, StreamingResponse
from starlette.middleware.cors import CORSMiddleware
from pathlib import Path
import shutil

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0",
)

DATABASE_FILE = "db.sqlite3"
PROFILE_PHOTOS_DIR = "profile_photos"

# Ensure the profile photos directory exists
Path(PROFILE_PHOTOS_DIR).mkdir(parents=True, exist_ok=True)

# Initialize the database
def init_db():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS profiles (
        username TEXT PRIMARY KEY,
        profile_page TEXT
    )
    """)
    conn.close()

init_db()

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    return HTTPException(status_code=500, detail="Internal Server Error")

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...), 
    profile_page: UploadFile = Form(...), 
    profile_photo: UploadFile = Form(...)
):
    # Check if username already exists
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM profiles WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=403, detail="Profile already exists")
    
    try:
        # Save HTML profile page content
        profile_content = await profile_page.read()
        cursor.execute("INSERT INTO profiles (username, profile_page) VALUES (?, ?)", (username, profile_content))
        
        # Save profile photo
        profile_photo_path = Path(PROFILE_PHOTOS_DIR, f"{username}.png")
        with open(profile_photo_path, "wb") as f:
            shutil.copyfileobj(profile_photo.file, f)
        
        conn.commit()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid input: {str(e)}")
    finally:
        conn.close()
    
    return {"detail": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Profile not found")

    profile_page = row[0]
    return HTMLResponse(content=profile_page)

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    profile_photo_path = Path(PROFILE_PHOTOS_DIR, f"{username}.png")
    if not profile_photo_path.exists():
        raise HTTPException(status_code=404, detail="Profile photo not found")

    def iterfile():
        with open(profile_photo_path, "rb") as file_like:
            yield from file_like

    return StreamingResponse(iterfile(), media_type="image/png")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)