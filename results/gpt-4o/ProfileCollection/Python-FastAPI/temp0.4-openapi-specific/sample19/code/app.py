import os
from fastapi import FastAPI, UploadFile, Form, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
import sqlite3
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

DATABASE = 'db.sqlite3'

# Initialize the database
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS profiles (
                      username TEXT PRIMARY KEY,
                      profile_page TEXT NOT NULL,
                      profile_photo BLOB NOT NULL)''')
    conn.commit()
    conn.close()

init_db()

@app.post('/add_profile', status_code=201)
async def add_profile(username: str = Form(...), profile_page: str = Form(...), profile_photo: UploadFile = Form(...)):
    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG")

    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Check if profile already exists
        cursor.execute("SELECT * FROM profiles WHERE username=?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists")

        photo_data = profile_photo.file.read()

        cursor.execute("INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
                       (username, profile_page, photo_data))
        conn.commit()
        conn.close()

    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail="Database error")

    return JSONResponse(status_code=201, content={"message": "Profile created successfully"})

@app.get('/profile/{username}', response_class=HTMLResponse)
async def get_profile(username: str):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT profile_page FROM profiles WHERE username=?", (username,))
        row = cursor.fetchone()
        conn.close()

        if row is None:
            raise HTTPException(status_code=404, detail="Profile not found")

    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail="Database error")

    return row[0]

@app.get('/profile-photo/{username}', response_class=FileResponse)
async def get_profile_photo(username: str):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT profile_photo FROM profiles WHERE username=?", (username,))
        row = cursor.fetchone()
        conn.close()

        if row is None:
            raise HTTPException(status_code=404, detail="Profile photo not found")

        photo_path = f"/tmp/{username}.png"
        with open(photo_path, "wb") as photo_file:
            photo_file.write(row[0])

    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail="Database error")

    return photo_path

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)