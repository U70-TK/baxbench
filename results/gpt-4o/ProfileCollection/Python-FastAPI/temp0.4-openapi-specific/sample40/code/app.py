from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, EmailStr, constr
from typing import Dict, Optional
import sqlite3
import os
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import Response

app = FastAPI()

DATABASE = "db.sqlite3"

app.add_middleware(SessionMiddleware, secret_key=os.getenv("APP_SECRET", "defaultsecret"))

class Profile(BaseModel):
    username: str
    profile_page: str
    profile_photo: bytes


def init_db():
    conn = sqlite3.connect(DATABASE)
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

@app.on_event("startup")
async def startup():
    init_db()


@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...),
):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG.")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
            (username, profile_page, profile_photo.file.read())
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=403, detail="Profile already exists.")
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail=str(e))
    
    conn.close()
    return {"message": "Profile created successfully"}


@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        return result[0]
    else:
        raise HTTPException(status_code=404, detail="Profile not found")


@app.get("/profile-photo/{username}", response_class=StreamingResponse)
async def get_profile_photo(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        return StreamingResponse(iter([result[0]]), media_type="image/png")
    else:
        raise HTTPException(status_code=404, detail="Profile photo not found")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)