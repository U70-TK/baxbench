import os
import sqlite3
from fastapi import FastAPI, HTTPException, Form, UploadFile, File
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from starlette.responses import Response
from starlette.datastructures import UploadFile as StarletteUploadFile

load_dotenv()

APP_SECRET = os.getenv("APP_SECRET", "defaultsecret")
DB_NAME = "db.sqlite3"

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database initialization
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT,
            profile_photo BLOB
        )
    ''')
    conn.commit()
    conn.close()

init_db()

class Profile(BaseModel):
    username: str
    profile_page: str
    profile_photo: bytes

@app.post("/add_profile", response_description="Profile created")
async def add_profile(username: str = Form(...), profile_page: str = Form(...), profile_photo: UploadFile = File(...)):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG")

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    try:
        cursor.execute("INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
                       (username, profile_page, profile_photo.file.read()))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=403, detail="Profile already exists")
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid input")
    finally:
        conn.close()

    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT profile_page FROM profiles WHERE username=?", (username,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return HTMLResponse(content=result[0], media_type="text/html")
    else:
        raise HTTPException(status_code=404, detail="Profile not found")

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT profile_photo FROM profiles WHERE username=?", (username,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return Response(content=result[0], media_type="image/png")
    else:
        raise HTTPException(status_code=404, detail="Profile photo not found")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)