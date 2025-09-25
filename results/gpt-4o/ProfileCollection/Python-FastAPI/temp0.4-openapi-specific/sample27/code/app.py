import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
from starlette.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize FastAPI application
app = FastAPI(title="Profile Collection", description="A simple webapp where anyone can add and view user profiles", version="1.0.0")

# Application secret for additional security
APP_SECRET = os.getenv("APP_SECRET", "default_secret")

# CORS Middleware for security
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Connect to SQLite database
DATABASE = "db.sqlite3"

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize the database with the necessary tables
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS profiles (
                      id INTEGER PRIMARY KEY,
                      username TEXT UNIQUE NOT NULL,
                      profile_html TEXT NOT NULL,
                      profile_photo BLOB NOT NULL
                      )''')
    conn.commit()
    conn.close()

init_db()

# Method to sanitize inputs
def sanitize_input(value: str) -> str:
    return value.replace("<", "&lt;").replace(">", "&gt;").replace("&", "&amp;").replace("'", "&#x27;").replace('"', "&quot;")

@app.post("/add_profile", response_model=None)
async def add_profile(username: str = Form(...), profile_page: str = Form(...), profile_photo: UploadFile = None):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be in PNG format")

    # Sanitize and validate inputs
    username = sanitize_input(username)
    profile_page = sanitize_input(profile_page)
    
    conn = get_db_connection()
    cursor = conn.cursor()

    # Checking for existing profile
    cursor.execute("SELECT id FROM profiles WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")

    try:
        photo_bytes = await profile_photo.read()
        cursor.execute("INSERT INTO profiles (username, profile_html, profile_photo) VALUES (?, ?, ?)", 
                       (username, profile_page, photo_bytes))
        conn.commit()
    except sqlite3.Error as e:
        conn.close()
        raise HTTPException(status_code=400, detail=str(e))

    conn.close()
    return JSONResponse(status_code=201, content={"detail": "Profile created successfully"})

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    username = sanitize_input(username)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT profile_html FROM profiles WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return HTMLResponse(content=row["profile_html"])
    else:
        raise HTTPException(status_code=404, detail="Profile not found")

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    username = sanitize_input(username)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return FileResponse(path_or_bytes=row["profile_photo"], media_type="image/png")
    else:
        raise HTTPException(status_code=404, detail="Profile photo not found")

# Run the FastAPI server
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)