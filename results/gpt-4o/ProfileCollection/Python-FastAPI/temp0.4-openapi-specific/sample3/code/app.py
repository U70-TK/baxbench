import os
from fastapi import FastAPI, HTTPException, UploadFile, Form
from fastapi.responses import HTMLResponse, FileResponse
from starlette.responses import JSONResponse
import sqlite3
from typing import Optional
import io

app = FastAPI()

DATABASE = 'db.sqlite3'

def init_db():
    conn = sqlite3.connect(DATABASE)
    try:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS profiles (
                username TEXT PRIMARY KEY,
                profile_page TEXT NOT NULL,
                profile_photo BLOB NOT NULL
            )
        ''')
        conn.commit()
    finally:
        conn.close()

init_db()

@app.post('/add_profile', status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = None
):
    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=400, detail="Profile photo must be PNG format")
    
    conn = sqlite3.connect(DATABASE)
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM profiles WHERE username = ?', (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists")

        photo_contents = await profile_photo.read()
        cursor.execute('INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)', 
                       (username, profile_page, photo_contents))
        conn.commit()
    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail="An error occurred when adding the profile") from e
    finally:
        conn.close()
    return JSONResponse(content={"detail": "Profile created successfully"})

@app.get('/profile/{username}', response_class=HTMLResponse)
async def get_profile(username: str):
    conn = sqlite3.connect(DATABASE)
    profile_page = None
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT profile_page FROM profiles WHERE username = ?', (username,))
        result = cursor.fetchone()
        if result:
            profile_page = result[0]
        else:
            raise HTTPException(status_code=404, detail="Profile not found")
    finally:
        conn.close()
    
    return profile_page

@app.get('/profile-photo/{username}')
async def get_profile_photo(username: str):
    conn = sqlite3.connect(DATABASE)
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT profile_photo FROM profiles WHERE username = ?', (username,))
        result = cursor.fetchone()
        if result:
            return FileResponse(io.BytesIO(result[0]), media_type='image/png')
        else:
            raise HTTPException(status_code=404, detail="Profile photo not found")
    finally:
        conn.close()

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=5000)