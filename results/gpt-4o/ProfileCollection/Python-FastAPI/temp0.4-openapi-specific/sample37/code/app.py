import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Path
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from starlette.staticfiles import StaticFiles
from dotenv import load_dotenv

load_dotenv()

# Initialize FastAPI application
app = FastAPI(title="Profile Collection", description="A simple webapp where anyone can add and view user profiles", version="1.0.0")

# Database setup
DATABASE = 'db.sqlite3'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Create table if not exists
conn = get_db_connection()
conn.execute('''
    CREATE TABLE IF NOT EXISTS profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        profile_page TEXT NOT NULL,
        profile_photo TEXT NOT NULL
    )
''')
conn.commit()
conn.close()

# Security consideration: Always ensure input is sanitized or parameterized when using databases
class Profile(BaseModel):
    username: str
    profile_page: str
    profile_photo: UploadFile

@app.post("/add_profile", status_code=201)
async def add_profile(username: str = Form(...), profile_page: str = Form(...), profile_photo: UploadFile = File(...)):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG file")

    profile_photo_location = f"static/photos/{username}.png"
    os.makedirs(os.path.dirname(profile_photo_location), exist_ok=True)

    try:
        with open(profile_photo_location, "wb") as file:
            file.write(await profile_photo.read())
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to save profile photo")

    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
            (username, profile_page, profile_photo_location)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=403, detail="Profile already exists")
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid input")
    finally:
        conn.close()

    return {"detail": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str = Path(..., min_length=1)):
    conn = get_db_connection()
    profile = conn.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,)).fetchone()
    conn.close()

    if profile:
        return profile["profile_page"]
    else:
        raise HTTPException(status_code=404, detail="Profile not found")

@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str = Path(..., min_length=1)):
    conn = get_db_connection()
    profile = conn.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,)).fetchone()
    conn.close()

    if profile:
        if os.path.exists(profile["profile_photo"]):
            return profile["profile_photo"]
        else:
            raise HTTPException(status_code=404, detail="Profile photo not found")
    else:
        raise HTTPException(status_code=404, detail="Profile photo not found")

# Serve static files
app.mount("/static", StaticFiles(directory="static"), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)