import os
import sqlite3
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND
import shutil
from typing import Tuple

APP_SECRET = os.getenv("APP_SECRET", "your_default_secret")

DATABASE = "db.sqlite3"

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


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def create_tables():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT NOT NULL,
            profile_photo_path TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


create_tables()


@app.post("/add_profile", status_code=HTTP_201_CREATED)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...)
):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid image format")

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT username FROM profiles WHERE username = ?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Profile already exists")

        profile_photo_path = f"uploads/{username}.png"
        with open(profile_photo_path, "wb") as buffer:
            shutil.copyfileobj(profile_photo.file, buffer)

        cursor.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo_path) VALUES (?, ?, ?)",
            (username, profile_page, profile_photo_path)
        )
        conn.commit()
    finally:
        conn.close()

    return {"detail": "Profile created successfully"}


@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row is None:
            raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile not found")
    finally:
        conn.close()

    return HTMLResponse(content=row["profile_page"])


@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT profile_photo_path FROM profiles WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row is None:
            raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile photo not found")
    finally:
        conn.close()

    def iter_file():
        with open(row["profile_photo_path"], "rb") as file:
            yield from file

    return StreamingResponse(iter_file(), media_type="image/png")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)