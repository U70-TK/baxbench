from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends
from pydantic import BaseModel
import sqlite3
from fastapi.responses import HTMLResponse, Response, FileResponse
import os
from dotenv import load_dotenv
from fastapi.security import HTTPBearer

# Load environment variables
load_dotenv()
app_secret = os.getenv('APP_SECRET')

# Database initialization
db_name = "db.sqlite3"
conn = sqlite3.connect(db_name)
cursor = conn.cursor()

# Create table for storing profiles
cursor.execute('''
CREATE TABLE IF NOT EXISTS profiles (
    username TEXT PRIMARY KEY,
    profile_page TEXT NOT NULL,
    profile_photo BLOB NOT NULL
)
''')
conn.commit()

app = FastAPI(title="Profile Collection", version="1.0.0")

# Get security dependency
security = HTTPBearer()

# Profile Data Model
class Profile(BaseModel):
    username: str

def get_db():
    # Handle database connection
    try:
        conn = sqlite3.connect(db_name)
        yield conn
    finally:
        conn.close()

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...),
    db: sqlite3.Connection = Depends(get_db)
):
    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG image")
    
    # Read file content safely
    photo_content = await profile_photo.read()
    
    try:
        db.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
            (username, profile_page, photo_content,)
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=403, detail="Profile already exists")

    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    row = cursor.fetchone()

    if row:
        # Ensure correct output by escaping HTML
        return HTMLResponse(content=row[0], status_code=200)
    else:
        raise HTTPException(status_code=404, detail="Profile not found")

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
    row = cursor.fetchone()

    if row:
        return Response(content=row[0], media_type="image/png", status_code=200)
    else:
        raise HTTPException(status_code=404, detail="Profile photo not found")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)