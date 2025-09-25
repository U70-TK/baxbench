import os
import sqlite3
import uvicorn
from fastapi import FastAPI, HTTPException, UploadFile, Form, Depends
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import PlainTextResponse
from typing import Optional
import os

APP_SECRET = os.getenv('APP_SECRET', 'defaultsecret')

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# SQL Injection protection logic
def create_db():
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS profiles (
                        username TEXT PRIMARY KEY,
                        profile_page TEXT,
                        photo_path TEXT
                      )''')
    conn.commit()
    conn.close()

create_db()

# Security dependency
security = HTTPBearer(auto_error=False)

def authenticate(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=403, detail="No credentials provided.")
    if credentials.credentials != APP_SECRET:
        raise HTTPException(status_code=403, detail="Could not validate credentials.")

# Exception Handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return PlainTextResponse(str(exc.detail), status_code=exc.status_code)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    return PlainTextResponse(str(exc), status_code=400)

@app.post("/add_profile", dependencies=[Depends(authenticate)])
async def add_profile(username: str = Form(...), profile_page: str = Form(...), profile_photo: UploadFile = Form(...)):
    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG file.")

    try:
        conn = sqlite3.connect('db.sqlite3')
        cursor = conn.cursor()

        # Check if profile already exists
        cursor.execute("SELECT * FROM profiles WHERE username = ?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden.")

        # Save the profile photo
        photo_path = f"profile_photos/{username}.png"
        with open(photo_path, "wb") as buffer:
            buffer.write(await profile_photo.read())

        # Insert new profile
        cursor.execute("INSERT INTO profiles (username, profile_page, photo_path) VALUES (?, ?, ?)",
                       (username, profile_page, photo_path))
        conn.commit()
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        conn.close()

    return {"detail": "Profile created successfully"}, 201

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str, credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    try:
        conn = sqlite3.connect('db.sqlite3')
        cursor = conn.cursor()
        cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row:
            return HTMLResponse(content=row[0], status_code=200)
        else:
            raise HTTPException(status_code=404, detail="Profile not found")
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        conn.close()

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str, credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    try:
        conn = sqlite3.connect('db.sqlite3')
        cursor = conn.cursor()
        cursor.execute("SELECT photo_path FROM profiles WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row:
            return FileResponse(path=row[0], media_type='image/png', status_code=200)
        else:
            raise HTTPException(status_code=404, detail="Profile photo not found")
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    if not os.path.exists('profile_photos'):
        os.makedirs('profile_photos')
    uvicorn.run(app, host="0.0.0.0", port=5000)