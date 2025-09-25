import os
import sqlite3
from fastapi import FastAPI, HTTPException, File, UploadFile, Form
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, validator
from starlette.responses import StreamingResponse
from dotenv import load_dotenv
import uvicorn

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

# Constants
DATABASE = "db.sqlite3"
FILE_DIR = "files"

# Load environment variables
load_dotenv()
APP_SECRET = os.getenv("APP_SECRET", "DEFAULT_SECRET")

# Setting up the SQLite database
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS profiles (
                        id INTEGER PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        profile_page TEXT NOT NULL,
                        profile_photo_path TEXT NOT NULL
                      )''')
    conn.close()

init_db()

# Set up Static File Path
app.mount("/static", StaticFiles(directory=FILE_DIR), name="static")

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/add_profile", status_code=201)
async def add_profile(username: str = Form(...), profile_page: UploadFile = Form(...), profile_photo: UploadFile = File(...)):
    # MIME type validation
    if profile_page.content_type != "text/html" or profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Invalid file type")

    # Read files and handle exceptions
    try:
        profile_page_content = await profile_page.read()
        profile_photo_content = await profile_photo.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    try:
        # Insert profile data with parameterized query to prevent SQL Injection
        cursor.execute(
            '''INSERT INTO profiles (username, profile_page, profile_photo_path)
               VALUES (?, ?, ?)''',
            (username, profile_page_content, f"{username}.png")
        )
        conn.commit()

        # Save the profile photo
        profile_photo_path = os.path.join(FILE_DIR, f"{username}.png")
        with open(profile_photo_path, "wb") as f:
            f.write(profile_photo_content)

    except sqlite3.IntegrityError as e:
        conn.rollback()
        if "UNIQUE constraint" in str(e):
            raise HTTPException(status_code=403, detail="Profile already exists")
        else:
            raise HTTPException(status_code=400, detail="Database error")
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        conn.close()
    
    return {"detail": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    try:
        cursor.execute(
            '''SELECT profile_page FROM profiles WHERE username=?''',
            (username,)
        )
        result = cursor.fetchone()
        if not result:
            raise HTTPException(status_code=404, detail="Profile not found")
        profile_page_content = result[0]
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        conn.close()

    return profile_page_content

@app.get("/profile-photo/{username}", response_class=Response)
async def get_profile_photo(username: str):
    try:
        profile_photo_path = os.path.join(FILE_DIR, f"{username}.png")
        if not os.path.exists(profile_photo_path):
            raise HTTPException(status_code=404, detail="Profile photo not found")
        
        with open(profile_photo_path, "rb") as f:
            profile_photo_content = f.read()
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Profile photo not found")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    return Response(content=profile_photo_content, media_type="image/png")

# Start the server
if __name__ == "__main__":
    # Ensure the directory for saving files exists
    os.makedirs(FILE_DIR, exist_ok=True)
    uvicorn.run(app, host="0.0.0.0", port=5000)