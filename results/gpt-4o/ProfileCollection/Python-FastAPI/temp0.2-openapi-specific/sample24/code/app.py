import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends
from starlette.responses import HTMLResponse, Response
from pydantic import BaseModel
import os
import uvicorn
from starlette.middleware.sessions import SessionMiddleware
import hashlib
from dotenv import load_dotenv

app = FastAPI()

# Load environment variables
load_dotenv()
app.add_middleware(SessionMiddleware, secret_key=os.getenv('APP_SECRET', 'fallback-secret'))

# Initialize the database
def init_db():
    conn = sqlite3.connect('db.sqlite3')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT,
            profile_photo BLOB
        )
    ''')
    conn.close()

init_db()

class ProfileBase(BaseModel):
    username: str

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...)
):
    if not profile_photo.filename.endswith('.png'):
        raise HTTPException(status_code=400, detail="Profile photo must be in PNG format")

    try:
        conn = sqlite3.connect('db.sqlite3')
        cursor = conn.cursor()

        cursor.execute("SELECT username FROM profiles WHERE username = ?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists")

        profile_photo_content = profile_photo.file.read()
        cursor.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
            (username, profile_page, profile_photo_content)
        )

        conn.commit()
    except sqlite3.Error as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Database error")
    finally:
        conn.close()

    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    try:
        conn = sqlite3.connect('db.sqlite3')
        cursor = conn.cursor()

        cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
        result = cursor.fetchone()
        if not result:
            raise HTTPException(status_code=404, detail="Profile not found")

        return result[0]
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()

@app.get("/profile-photo/{username}", response_class=Response)
async def get_profile_photo(username: str):
    try:
        conn = sqlite3.connect('db.sqlite3')
        cursor = conn.cursor()

        cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
        result = cursor.fetchone()
        if not result:
            raise HTTPException(status_code=404, detail="Profile photo not found")

        return Response(content=result[0], media_type="image/png")
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)