import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Constants
DATABASE = 'db.sqlite3'
APP_SECRET = os.getenv('APP_SECRET', 'defaultsecret')

# Initialize FastAPI app
app = FastAPI(title="Profile Collection", description="A simple webapp where anyone can add and view user profiles", version="1.0.0")

# Ensure database and table exist
conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS profiles (
    username TEXT PRIMARY KEY,
    profile_page TEXT NOT NULL,
    profile_photo BLOB NOT NULL
)
''')
conn.commit()
conn.close()

# Helper functions
def add_profile_to_db(username, profile_page, profile_photo):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
                       (username, profile_page, profile_photo))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid input: {str(e)}")
    finally:
        conn.close()

def get_profile_from_db(username):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]
    else:
        raise HTTPException(status_code=404, detail="Profile not found")

def get_profile_photo_from_db(username):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]
    else:
        raise HTTPException(status_code=404, detail="Profile photo not found")

# API endpoints
@app.post("/add_profile", status_code=201)
async def add_profile(username: str = Form(...), profile_page: str = Form(...), profile_photo: UploadFile = File(...)):
    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=400, detail="Profile photo must be in PNG format")
    
    profile_photo_data = await profile_photo.read()
    add_profile_to_db(username, profile_page, profile_photo_data)
    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    profile_page = get_profile_from_db(username)
    return HTMLResponse(content=profile_page, status_code=200)

@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    profile_photo = get_profile_photo_from_db(username)
    return Response(content=profile_photo, media_type="image/png", status_code=200)

# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=5000)