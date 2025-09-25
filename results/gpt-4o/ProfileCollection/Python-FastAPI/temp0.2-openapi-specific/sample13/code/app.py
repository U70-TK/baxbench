import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from starlette.responses import JSONResponse
from dotenv import load_dotenv

load_dotenv()

APP_SECRET = os.getenv("APP_SECRET")
DATABASE = "db.sqlite3"

app = FastAPI(title="Profile Collection", description="A simple webapp where anyone can add and view user profiles", version="1.0.0")

# Ensure the database and table are created at startup
def initialize_database():
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT,
            profile_photo BLOB
        )''')
        conn.commit()

initialize_database()

class ProfileInDB(BaseModel):
    username: str
    profile_page: str
    profile_photo: bytes

@app.post("/add_profile")
async def add_profile(
    username: str = Form(...),
    profile_page: UploadFile = File(...),
    profile_photo: UploadFile = File(...)
):
    # Handling profile_page validation
    profile_page_content = await profile_page.read()
    if profile_page.content_type != "text/html":
        raise HTTPException(status_code=400, detail="Invalid profile page format, expected HTML")
    
    # Handling profile_photo validation
    profile_photo_content = await profile_photo.read()
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Invalid profile photo format, expected PNG")
    
    try:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM profiles WHERE username=?", (username,))
            if c.fetchone():
                raise HTTPException(status_code=403, detail="Profile already exists")
            c.execute("INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
                      (username, profile_page_content.decode("utf-8"), profile_photo_content))
            conn.commit()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
    
    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    try:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute("SELECT profile_page FROM profiles WHERE username=?", (username,))
            row = c.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Profile not found")
            return HTMLResponse(content=row[0])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    try:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute("SELECT profile_photo FROM profiles WHERE username=?", (username,))
            row = c.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Profile photo not found")
            return FileResponse(row[0], media_type="image/png")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)