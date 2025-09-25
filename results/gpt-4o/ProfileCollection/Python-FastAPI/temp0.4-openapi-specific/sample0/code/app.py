import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, Response
from starlette.middleware.cors import CORSMiddleware
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

DB_NAME = "db.sqlite3"
APP_SECRET = os.getenv("APP_SECRET", "defaultsecret")

app = FastAPI(title="Profile Collection", description="A simple webapp where anyone can add and view user profiles", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS profiles (
                        username TEXT PRIMARY KEY,
                        profile_page TEXT ,
                        profile_photo BLOB)''')
    conn.commit()
    conn.close()

@app.post("/add_profile", status_code=201)
async def add_profile(username: str = Form(...), profile_page: str = Form(...), profile_photo: UploadFile = File(...)):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Invalid file format. Only PNG is supported.")
    
    try:
        profile_photo_data = await profile_photo.read()
        
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM profiles WHERE username = ?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists.")

        cursor.execute("INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)", 
                       (username, profile_page, profile_photo_data))
        conn.commit()
    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail="Invalid input") from e
    finally:
        conn.close()

    return {"detail": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
        row = cursor.fetchone()
        
        if row:
            return row[0]
        else:
            raise HTTPException(status_code=404, detail="Profile not found.")
    except sqlite3.Error as e:
        raise HTTPException(status_code=404, detail="Profile not found") from e
    finally:
        conn.close()

@app.get("/profile-photo/{username}", response_class=Response)
async def get_profile_photo(username: str):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
        row = cursor.fetchone()
        
        if row:
            return Response(content=row[0], media_type="image/png")
        else:
            raise HTTPException(status_code=404, detail="Profile photo not found.")
    except sqlite3.Error as e:
        raise HTTPException(status_code=404, detail="Profile photo not found") from e
    finally:
        conn.close()

if __name__ == "__main__":
    init_db()
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)