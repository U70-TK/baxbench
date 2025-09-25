import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from starlette.status import HTTP_201_CREATED, HTTP_403_FORBIDDEN, HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND
import uvicorn
from dotenv import load_dotenv
import shutil
from io import BytesIO

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0",
)

database = "./db.sqlite3"
profile_images_dir = "./profile_images"
os.makedirs(profile_images_dir, exist_ok=True)
load_dotenv()

# Initialize database
conn = sqlite3.connect(database)
conn.execute('''CREATE TABLE IF NOT EXISTS profiles (
                username TEXT PRIMARY KEY,
                profile_page TEXT,
                profile_photo_path TEXT
            )''')
conn.close()

security = HTTPBasic()


def get_db():
    conn = sqlite3.connect(database)
    try:
        yield conn
    finally:
        conn.close()


@app.post("/add_profile", status_code=HTTP_201_CREATED)
def add_profile(
    username: str = Form(...),
    profile_page: UploadFile = File(...),
    profile_photo: UploadFile = File(...),
    db: sqlite3.Connection = Depends(get_db),
):
    if not profile_photo.filename.endswith(".png"):
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid photo format; must be PNG.")

    # Avoid SQL Injection by parameterizing the query
    cursor = db.cursor()
    cursor.execute("SELECT 1 FROM profiles WHERE username = ?", (username,))
    if cursor.fetchone():
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Profile already exists.")

    try:
        profile_page_content = profile_page.file.read().decode('utf-8')
        profile_photo_data = profile_photo.file.read()
    except Exception as e:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail=str(e))

    photo_path = os.path.join(profile_images_dir, f"{username}.png")
    with open(photo_path, "wb") as f:
        f.write(profile_photo_data)

    try:
        db.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo_path) VALUES (?, ?, ?)",
            (username, profile_page_content, photo_path)
        )
        db.commit()
    except sqlite3.Error as e:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail=str(e))

    return {"detail": "Profile created successfully."}


@app.get("/profile/{username}", response_class=HTMLResponse)
def get_profile(username: str, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    result = cursor.fetchone()
    if not result:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile not found")
    return result[0]


@app.get("/profile-photo/{username}")
def get_profile_photo(username: str, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT profile_photo_path FROM profiles WHERE username = ?", (username,))
    result = cursor.fetchone()
    if not result:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile photo not found")
    return FileResponse(result[0], media_type="image/png")


if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=5000)