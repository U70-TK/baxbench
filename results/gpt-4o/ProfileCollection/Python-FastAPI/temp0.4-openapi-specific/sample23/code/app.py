import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import RedirectResponse
from starlette.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND
import uvicorn

DATABASE = 'db.sqlite3'
app = FastAPI(title="Profile Collection WebApp", description="A simple webapp where anyone can add and view user profiles.")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure database setup
def setup_database():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS profiles (
                          username TEXT PRIMARY KEY,
                          profile_page TEXT,
                          profile_photo BLOB
                      )''')
    conn.commit()
    conn.close()

setup_database()

# Utility function to check profile existence
def profile_exists(username):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM profiles WHERE username = ?", (username,))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists

# Add a new user profile
@app.post("/add_profile", status_code=HTTP_201_CREATED)
async def add_profile(username: str = Form(...), profile_page: UploadFile = File(...), profile_photo: UploadFile = File(...)):
    if profile_exists(username):
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Profile already exists")

    try:
        profile_page_content = (await profile_page.read()).decode("utf-8")
        profile_photo_content = await profile_photo.read()
    except Exception as e:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid input") from e

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
                       (username, profile_page_content, profile_photo_content))
        conn.commit()
    except sqlite3.Error as e:
        conn.rollback()
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Error saving profile to database") from e
    finally:
        conn.close()

    return JSONResponse(content={"message": "Profile created successfully"}, status_code=HTTP_201_CREATED)

# Get user profile
@app.get("/profile/{username}", response_class=HTMLResponse, responses={200: {"description": "Profile retrieved successfully"}})
async def get_profile(username: str):
    if not profile_exists(username):
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile not found")
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if not result:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile not found")

    html_content = result[0]
    return HTMLResponse(content=html_content)

# Get user profile photo
@app.get("/profile-photo/{username}", responses={200: {"content": {"image/png": {}}}, 404: {"description": "Profile photo not found"}})
async def get_profile_photo(username: str):
    if not profile_exists(username):
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile photo not found")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if not result or not result[0]:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile photo not found")

    return FileResponse(path_or_file=result[0], media_type='image/png')

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)