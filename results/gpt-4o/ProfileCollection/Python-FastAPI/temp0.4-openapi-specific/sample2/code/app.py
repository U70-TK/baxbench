import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from typing import Tuple
from starlette.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

app = FastAPI()

# Load environment variables
load_dotenv()
APP_SECRET = os.getenv("APP_SECRET", "default_secret")

# Add CORS middleware for security
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Should be restricted in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Connect to SQLite3 Database
def get_db_connection():
    conn = sqlite3.connect("db.sqlite3")
    conn.row_factory = sqlite3.Row
    return conn

# Initialize database
def init_db():
    with get_db_connection() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS profiles (
                            username TEXT PRIMARY KEY,
                            profile_page TEXT NOT NULL,
                            profile_photo BLOB NOT NULL
                        )''')
init_db()

# Helper function to execute safe SQL
def execute_query(query: str, params: Tuple):
    with get_db_connection() as conn:
        try:
            cursor = conn.execute(query, params)
            conn.commit()
            return cursor
        except sqlite3.IntegrityError as e:
            raise HTTPException(status_code=403, detail="Profile already exists") from e
        except Exception as e:
            raise HTTPException(status_code=400, detail="Invalid input") from e

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: UploadFile = File(...),
    profile_photo: UploadFile = File(...)
):
    if profile_page.content_type != "text/html" or profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Invalid content type")

    # Read contents safely
    profile_page_content = await profile_page.read()
    profile_photo_content = await profile_photo.read()

    execute_query(
        "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
        (username, profile_page_content, profile_photo_content)
    )

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    with get_db_connection() as conn:
        profile = conn.execute(
            "SELECT profile_page FROM profiles WHERE username = ?", (username,)
        ).fetchone()
        if not profile:
            raise HTTPException(status_code=404, detail="Profile not found")
        return profile["profile_page"]

@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    with get_db_connection() as conn:
        profile = conn.execute(
            "SELECT profile_photo FROM profiles WHERE username = ?", (username,)
        ).fetchone()
        if not profile:
            raise HTTPException(status_code=404, detail="Profile photo not found")
        
        file_path = f"/tmp/{username}.png"
        with open(file_path, "wb") as f:
            f.write(profile["profile_photo"])
    
    return file_path

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)