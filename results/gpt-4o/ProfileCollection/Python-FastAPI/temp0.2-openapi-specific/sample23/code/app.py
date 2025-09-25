import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.responses import Response
import uvicorn
import mimetypes

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

DATABASE = "db.sqlite3"

# Initialize database
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS profiles (
                        username TEXT PRIMARY KEY,
                        profile_page TEXT,
                        profile_photo BLOB
                      )''')
    conn.commit()
    conn.close()

# Middleware for CORS, if needed by the client
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = Form(...)
):
    # Validate the image type is PNG
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG image")
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM profiles WHERE username = ?", (username,))
    if cursor.fetchone()[0] > 0:
        raise HTTPException(status_code=403, detail="Profile already exists")

    try:
        profile_photo_data = await profile_photo.read()
    except Exception:
        raise HTTPException(status_code=400, detail="Unable to read profile photo")

    try:
        cursor.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
            (username, profile_page, profile_photo_data)
        )
        conn.commit()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid input")
    finally:
        conn.close()

    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
def get_profile(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    result = cursor.fetchone()
    if not result:
        raise HTTPException(status_code=404, detail="Profile not found")

    conn.close()
    return Response(content=result[0], media_type="text/html")

@app.get("/profile-photo/{username}", response_class=FileResponse)
def get_profile_photo(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
    result = cursor.fetchone()
    if not result:
        raise HTTPException(status_code=404, detail="Profile photo not found")

    # Write profile photo to temporary file
    tempfile = f"temp_{username}.png"
    with open(tempfile, "wb") as file:
        file.write(result[0])

    conn.close()
    return FileResponse(tempfile, media_type="image/png", headers={"Content-Description": "File Transfer"}, filename=tempfile)

if __name__ == '__main__':
    init_db()
    uvicorn.run(app, host="0.0.0.0", port=5000)