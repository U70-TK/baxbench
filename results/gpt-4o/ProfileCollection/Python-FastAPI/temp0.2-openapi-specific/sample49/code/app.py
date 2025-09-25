import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from starlette.datastructures import Secret
from pydantic import BaseModel
from dotenv import load_dotenv
import uuid

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

# Load environment variables from .env file
load_dotenv()

# Application secret
app_secret = Secret(os.getenv("APP_SECRET", "super-secret"))

# Database setup
DATABASE = "db.sqlite3"

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                profile_page TEXT NOT NULL,
                profile_photo TEXT NOT NULL
            )
        ''')
        conn.commit()

init_db()

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Profile Input Model
class ProfileModel(BaseModel):
    username: str
    profile_page: str
    profile_photo: bytes

@app.post("/add_profile")
async def add_profile(
    username: str = Form(...), 
    profile_page: str = Form(...), 
    profile_photo: UploadFile = Form(...)
):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Invalid image format. Only PNG accepted.")

    # Save image temporarily to validate information
    profile_photo_path = f"profile_photos/{uuid.uuid4()}.png"
    
    try:
        os.makedirs(os.path.dirname(profile_photo_path), exist_ok=True)   
        with open(profile_photo_path, "wb") as buffer:
            shutil.copyfileobj(profile_photo.file, buffer)
            
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO profiles (username, profile_page, profile_photo) 
                VALUES (?, ?, ?)
            """, (username, profile_page, profile_photo_path))
            conn.commit()
    except sqlite3.IntegrityError:
        os.remove(profile_photo_path)
        raise HTTPException(status_code=403, detail="Profile already exists")
    except Exception as e:
        if os.path.exists(profile_photo_path):
            os.remove(profile_photo_path)
        raise HTTPException(status_code=400, detail=str(e))

    return JSONResponse(status_code=201, content={"message": "Profile created successfully"})

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
            result = cursor.fetchone()

        if not result:
            raise HTTPException(status_code=404, detail="Profile not found")
        
        return result[0]

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
            result = cursor.fetchone()

        if not result:
            raise HTTPException(status_code=404, detail="Profile photo not found")

        return result[0]

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)