import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends
from pydantic import BaseModel
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.security import HTTPBearer
from starlette.middleware.cors import CORSMiddleware

# Environment variable for application secret
APP_SECRET = os.getenv("APP_SECRET", "default_secret")

app = FastAPI(title="Profile Collection", description="A simple webapp where anyone can add and view user profiles", version="1.0.0")

# Apply CORS middleware
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Database connection and initialization
def get_db():
    conn = sqlite3.connect("db.sqlite3")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_profiles (
        username TEXT PRIMARY KEY,
        profile_page TEXT,
        profile_photo BLOB
    )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: UploadFile = File(...),
    profile_photo: UploadFile = File(...),
    token: str = Depends(HTTPBearer(auto_error=False))
):
    if not token or token.credentials != APP_SECRET:
        raise HTTPException(status_code=403, detail="Invalid authentication credentials")

    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Check if the username already exists
        cursor.execute("SELECT * FROM user_profiles WHERE username = ?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists")

        # Read profile page content
        html_content = await profile_page.read()
        # Read profile photo content, ensure it is a PNG
        if profile_photo.content_type != 'image/png':
            raise HTTPException(status_code=400, detail="Profile photo must be a PNG")
        photo_content = await profile_photo.read()

        # Insert the new profile into the database
        cursor.execute(
            "INSERT INTO user_profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
            (username, html_content, photo_content)
        )
        conn.commit()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        conn.close()
    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT profile_page FROM user_profiles WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Profile not found")
        return row["profile_page"]
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        conn.close()

@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT profile_photo FROM user_profiles WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Profile photo not found")
        photo_path = f"/tmp/{username}_photo.png"
        with open(photo_path, "wb") as f:
            f.write(row["profile_photo"])
        return photo_path
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        conn.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)