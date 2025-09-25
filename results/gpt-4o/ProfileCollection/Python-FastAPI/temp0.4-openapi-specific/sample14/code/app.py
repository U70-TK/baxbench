import os
import sqlite3
import uvicorn
from fastapi import FastAPI, HTTPException, File, Form, UploadFile
from fastapi.responses import HTMLResponse, FileResponse
from pathlib import Path
from pydantic import BaseModel

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

DATABASE = "db.sqlite3"
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
APP_SECRET = os.getenv("APP_SECRET", "default_secret")

# Database setup
def init_db():
    con = sqlite3.connect(DATABASE)
    cur = con.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        profile_page TEXT NOT NULL
    )''')
    con.commit()
    con.close()

init_db()

class Profile(BaseModel):
    username: str
    profile_page: str

# Helper functions
def db_execute(query, params=()):
    con = sqlite3.connect(DATABASE)
    cur = con.cursor()
    try:
        cur.execute(query, params)
        con.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"An error occurred: {str(e)}")
    finally:
        con.close()

def db_query(query, params=()):
    con = sqlite3.connect(DATABASE)
    cur = con.cursor()
    result = cur.execute(query, params).fetchall()
    con.close()
    return result

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...), 
    profile_page: str = Form(...), 
    profile_photo: UploadFile = File(...)
):
    # Input validation
    if not profile_photo.filename.endswith(".png"):
        raise HTTPException(status_code=400, detail="Profile photo must be in PNG format")

    # Save profile photo securely
    photo_path = UPLOAD_DIR / f"{username}.png"
    with photo_path.open("wb") as f:
        f.write(await profile_photo.read())

    # Save profile info to the database
    db_execute(
        "INSERT INTO profiles (username, profile_page) VALUES (?, ?)", 
        (username, profile_page)
    )

    return {"detail": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    result = db_query("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    if not result:
        raise HTTPException(status_code=404, detail="Profile not found")
    return result[0][0]

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    photo_path = UPLOAD_DIR / f"{username}.png"
    if not photo_path.exists():
        raise HTTPException(status_code=404, detail="Profile photo not found")
    return FileResponse(photo_path, media_type="image/png")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)