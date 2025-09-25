import os
import sqlite3
from fastapi import FastAPI, HTTPException, File, UploadFile, Form
from fastapi.responses import HTMLResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.responses import FileResponse
from starlette.status import HTTP_201_CREATED, HTTP_404_NOT_FOUND, HTTP_400_BAD_REQUEST, HTTP_403_FORBIDDEN

APP_SECRET = os.getenv("APP_SECRET", "super_secret_string")

# Database setup
def init_db():
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT NOT NULL,
            profile_photo BLOB NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Profile(BaseModel):
    username: str
    profile_page: str
    profile_photo: bytes

@app.post("/add_profile")
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...)
):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid profile photo format")
    
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
                       (username, profile_page, profile_photo.file.read()))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Profile already exists")
    finally:
        conn.close()

    return {"detail": "Profile created successfully"}, HTTP_201_CREATED

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if not result:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile not found")

    return HTMLResponse(result[0])

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if not result:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile photo not found")

    return Response(content=result[0], media_type="image/png")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)