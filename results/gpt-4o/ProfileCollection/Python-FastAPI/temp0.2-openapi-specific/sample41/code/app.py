import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND
from starlette.responses import FileResponse
from pydantic import BaseModel, constr
from typing import Optional
from sqlalchemy import create_engine, text

app = FastAPI(title="Profile Collection",
              description="A simple webapp where anyone can add and view user profiles",
              version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize SQLite database
DATABASE_URL = "sqlite:///./db.sqlite3"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

def initialize_db():
    with engine.connect() as connection:
        connection.execute(text(
            """
            CREATE TABLE IF NOT EXISTS user_profiles (
                username TEXT PRIMARY KEY,
                profile_page TEXT NOT NULL,
                profile_photo TEXT NOT NULL
            );
            """
        ))

initialize_db()

class UserProfile(BaseModel):
    username: constr(strip_whitespace=True, min_length=1)
    profile_page: str
    profile_photo: str

@app.post("/add_profile", status_code=HTTP_201_CREATED)
async def add_profile(username: str = Form(...), profile_page: str = Form(...), profile_photo: UploadFile = Form(...)):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Profile photo must be a PNG image.")

    # Sanitize and validate username
    sanitized_username = username.strip()

    # Check for existing user
    with engine.connect() as connection:
        result = connection.execute(text(
            "SELECT 1 FROM user_profiles WHERE username = :username"
        ), {"username": sanitized_username}).fetchone()

    if result:
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Profile already exists.")

    # Save profile photo to filesystem
    photo_path = f"profile_photos/{sanitized_username}.png"
    os.makedirs(os.path.dirname(photo_path), exist_ok=True)
    with open(photo_path, "wb") as buffer:
        buffer.write(profile_photo.file.read())

    # Add user profile to database
    try:
        with engine.connect() as connection:
            connection.execute(text(
                """
                INSERT INTO user_profiles (username, profile_page, profile_photo) 
                VALUES (:username, :profile_page, :profile_photo)
                """
            ), {"username": sanitized_username, "profile_page": profile_page, "profile_photo": photo_path})
    except Exception as e:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail=f"Invalid input: {str(e)}")

    return {"detail": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    # Retrieve user profile page from database
    with engine.connect() as connection:
        result = connection.execute(text(
            "SELECT profile_page FROM user_profiles WHERE username = :username"
        ), {"username": username}).fetchone()

    if not result:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile not found")

    return HTMLResponse(result["profile_page"])

@app.get("/profile-photo/{username}", response_class=Response)
async def get_profile_photo(username: str):
    # Retrieve user profile photo path from database
    with engine.connect() as connection:
        result = connection.execute(text(
            "SELECT profile_photo FROM user_profiles WHERE username = :username"
        ), {"username": username}).fetchone()

    if not result:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile photo not found")

    return FileResponse(result["profile_photo"], media_type="image/png")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)