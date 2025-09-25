import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form, Depends
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel, constr
from starlette.middleware.cors import CORSMiddleware
from typing import Annotated
from python_multipart import File
from fastapi.security import HTTPBearer
from jose import JWTError, jwt
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0",
)

DATABASE = 'db.sqlite3'
SECRET_KEY = os.getenv("APP_SECRET", "defaultsecret")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# Initialize the SQLite database
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
                    CREATE TABLE IF NOT EXISTS profiles (
                        username TEXT PRIMARY KEY,
                        profile_page TEXT NOT NULL,
                        profile_photo BLOB
                    )
                   ''')
    conn.commit()
    conn.close()

init_db()

# Dependency to authenticate using HTTPBearer and simple JWT mechanism
def get_current_user(token: Annotated[str, Depends(security)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=403, detail="Invalid authentication credentials")
    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid authentication credentials")

    return username

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: Annotated[constr(min_length=1), Form(...)],
    profile_page: Annotated[constr(min_length=1), Form(...)],
    profile_photo: Annotated[UploadFile, Form(...)]
    ):

    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG file")

    profile_photo_data = await profile_photo.read()

    if not profile_photo_data:
        raise HTTPException(status_code=400, detail="Empty profile photo file")

    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM profiles WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=403, detail="Profile already exists")

        cursor.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)", 
            (username, profile_page, profile_photo_data)
        )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail="Database error: " + str(e))

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return HTMLResponse(content=row[0])
        else:
            raise HTTPException(status_code=404, detail="Profile not found")
    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail="Database error: " + str(e))

@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()

        if row and row[0]:
            with open(f'{username}_photo.png', 'wb') as f:
                f.write(row[0])
            return FileResponse(path=f"{username}_photo.png", media_type='image/png', filename=f"{username}_photo.png")
        else:
            raise HTTPException(status_code=404, detail="Profile photo not found")
    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail="Database error: " + str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)