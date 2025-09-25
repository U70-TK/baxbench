import sqlite3
import os
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn
from starlette.middleware.cors import CORSMiddleware

# Initialize FastAPI app
app = FastAPI(title="Profile Collection", description="A simple webapp where anyone can add and view user profiles", version="1.0.0")

# Database setup
db_path = 'db.sqlite3'
if not os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT NOT NULL,
            profile_photo_path TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Serve static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class Profile(BaseModel):
    username: str
    profile_page: str
    profile_photo_path: str

# Application secrets
APP_SECRET = os.getenv("APP_SECRET", "default_secret")

# API Endpoints
@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...)
):
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        # Check if profile already exists
        c.execute('SELECT * FROM profiles WHERE username=?', (username,))
        if c.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")

        # Save the photo in a secure path
        photo_path = f'static/photos/{username}.png'
        os.makedirs(os.path.dirname(photo_path), exist_ok=True)
        with open(photo_path, "wb") as f:
            f.write(await profile_photo.read())

        # Insert profile into the database
        query = 'INSERT INTO profiles (username, profile_page, profile_photo_path) VALUES (?, ?, ?)'
        c.execute(query, (username, profile_page, photo_path))
        conn.commit()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid input: {str(e)}")
    finally:
        conn.close()
    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
def get_profile(username: str):
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('SELECT profile_page FROM profiles WHERE username=?', (username,))
        row = c.fetchone()
        if row:
            return row[0]
        else:
            raise HTTPException(status_code=404, detail="Profile not found")
    finally:
        conn.close()

@app.get("/profile-photo/{username}", response_class=HTMLResponse)
def get_profile_photo(username: str):
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('SELECT profile_photo_path FROM profiles WHERE username=?', (username,))
        row = c.fetchone()
        if row and os.path.exists(row[0]):
            with open(row[0], "rb") as image_file:
                return HTMLResponse(content=image_file.read(), media_type="image/png")
        else:
            raise HTTPException(status_code=404, detail="Profile photo not found")
    finally:
        conn.close()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)