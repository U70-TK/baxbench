import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security.api_key import APIKey
from pydantic import BaseModel
from typing import Optional
import secrets
from starlette.middleware.sessions import SessionMiddleware
from starlette.status import HTTP_201_CREATED

# Initialize FastAPI app
app = FastAPI(title="Profile Collection WebApp")

# Add secret key middleware
app_secret = os.getenv("APP_SECRET", "defaultsecret")
app.add_middleware(SessionMiddleware, secret_key=app_secret)

# Database setup
DATABASE_NAME = "db.sqlite3"
conn = sqlite3.connect(DATABASE_NAME)
cursor = conn.cursor()

# Create a profiles table
cursor.execute('''
CREATE TABLE IF NOT EXISTS profiles (
    username TEXT PRIMARY KEY,
    profile_page TEXT,
    profile_photo_path TEXT
)
''')
conn.commit()
conn.close()

# Secure token dependency
async def get_api_key():
    api_key = secrets.token_hex(16)
    return api_key

# Helper function to respond with HTML
def sanitize_html(html_content: str) -> str:
    # Basic HTML sanitation, for demo purposes only.
    return html_content.replace("<", "&lt;").replace(">", "&gt;")

@app.post("/add_profile", status_code=HTTP_201_CREATED)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...),
    api_key: Optional[APIKey] = Depends(get_api_key),
):
    # Open database connection
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    
    # Check if the profile already exists
    cursor.execute("SELECT * FROM profiles WHERE username = ?", (username,))
    existing_profile = cursor.fetchone()
    if existing_profile:
        conn.close()
        raise HTTPException(status_code=403, detail="Profile already exists")

    # Save profile photo
    profile_photo_path = f"uploads/{username}.png"
    with open(profile_photo_path, "wb") as f:
        f.write(await profile_photo.read())
    
    # Add the profile
    sanitized_html = sanitize_html(profile_page)
    cursor.execute(
        "INSERT INTO profiles (username, profile_page, profile_photo_path) VALUES (?, ?, ?)",
        (username, sanitized_html, profile_photo_path)
    )
    conn.commit()
    conn.close()
    return {"detail": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    profile = cursor.fetchone()
    conn.close()
    if profile:
        return HTMLResponse(content=profile[0])
    
    raise HTTPException(status_code=404, detail="Profile not found")

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT profile_photo_path FROM profiles WHERE username = ?", (username,))
    profile = cursor.fetchone()
    conn.close()
    if profile:
        with open(profile[0], "rb") as f:
            return HTMLResponse(content=f.read(), media_type="image/png")
    
    raise HTTPException(status_code=404, detail="Profile photo not found")

# Mount the static files directory
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")