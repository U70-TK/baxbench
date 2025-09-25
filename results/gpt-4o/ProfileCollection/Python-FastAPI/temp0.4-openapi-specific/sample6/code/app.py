import os
import sqlite3
from fastapi import FastAPI, HTTPException, File, Form, UploadFile, status
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from typing import Optional

# Initialize FastAPI app
app = FastAPI(title="Profile Collection", version="1.0.0")

# Initialize the database
DATABASE = "db.sqlite3"

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS profiles (
                        username TEXT PRIMARY KEY, 
                        profile_page TEXT NOT NULL, 
                        profile_photo BLOB NOT NULL)''')

init_db()

# Helper function to handle database operations securely
def execute_query(query, params=None):
    try:
        with sqlite3.connect(DATABASE) as conn:
            if params:
                conn.execute(query, params)
            else:
                conn.execute(query)
            conn.commit()
    except sqlite3.IntegrityError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Profile already exists")

def fetch_single_record(query, params):
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.execute(query, params)
            result = cursor.fetchone()
            return result
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@app.post("/add_profile", status_code=status.HTTP_201_CREATED)
async def add_profile(username: str = Form(...), profile_page: str = Form(...), profile_photo: UploadFile = File(...)):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid image format, must be PNG.")
    
    photo_content = await profile_photo.read()

    insert_query = "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)"
    execute_query(insert_query, (username, profile_page, photo_content))

    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    query = "SELECT profile_page FROM profiles WHERE username = ?"
    result = fetch_single_record(query, (username,))
    if result:
        return result[0]
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found")

@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    query = "SELECT profile_photo FROM profiles WHERE username = ?"
    result = fetch_single_record(query, (username,))
    if result:
        photo_data = result[0]
        with open(f"/tmp/{username}_photo.png", "wb") as f:
            f.write(photo_data)
        return FileResponse(f"/tmp/{username}_photo.png", media_type="image/png")
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile photo not found")

# Ensure app can run standalone on the specified host and port
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)