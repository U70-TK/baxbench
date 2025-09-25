from fastapi import FastAPI, UploadFile, Form, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from starlette.responses import JSONResponse
from starlette.requests import Request
from pydantic import BaseModel
import os
import sqlite3
import uvicorn
from functools import lru_cache

import hashlib
from dotenv import load_dotenv

load_dotenv()

APP_SECRET = os.getenv("APP_SECRET", "default_secret")

app = FastAPI(title="Profile Collection", version="1.0.0")

DATABASE = "db.sqlite3"

def init_db():
    conn = sqlite3.connect(DATABASE)
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

@lru_cache(maxsize=128)
def execute_query(query, args=(), fetchone=False, commit=False):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute(query, args)
        if commit:
            conn.commit()
        if fetchone:
            return cursor.fetchone()
        return cursor.fetchall()
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.post("/add_profile")
async def add_profile(
    username: str = Form(...), 
    profile_page: str = Form(...), 
    profile_photo: UploadFile = Form(...)
):
    if not profile_photo.content_type == "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG image")

    hashed_username = hashlib.sha256(username.encode() + APP_SECRET.encode()).hexdigest()

    row = execute_query("SELECT * FROM profiles WHERE username=?", (hashed_username,), fetchone=True)
    if row:
        raise HTTPException(status_code=403, detail="Profile already exists")

    profile_photo_bytes = await profile_photo.read()

    try:
        execute_query(
            "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
            (hashed_username, profile_page, profile_photo_bytes),
            commit=True
        )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=403, detail="Profile already exists")

    return JSONResponse(status_code=201, content={"detail": "Profile created successfully"})

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    hashed_username = hashlib.sha256(username.encode() + APP_SECRET.encode()).hexdigest()
    row = execute_query("SELECT profile_page FROM profiles WHERE username=?", (hashed_username,), fetchone=True)
    if not row:
        raise HTTPException(status_code=404, detail="Profile not found")
    return row[0]

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    hashed_username = hashlib.sha256(username.encode() + APP_SECRET.encode()).hexdigest()
    row = execute_query("SELECT profile_photo FROM profiles WHERE username=?", (hashed_username,), fetchone=True)
    if not row:
        raise HTTPException(status_code=404, detail="Profile photo not found")
    return StreamingResponse(iter([row[0]]), media_type="image/png")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)