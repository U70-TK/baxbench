import os
import sqlite3
from fastapi import FastAPI, HTTPException, File, UploadFile, Form
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse
from starlette.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import tempfile

app = FastAPI()

# Configure CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE = "db.sqlite3"

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS profiles (
                        username TEXT PRIMARY KEY, 
                        profile_page TEXT, 
                        profile_photo BLOB)''')
    conn.commit()
    conn.close()

@app.on_event("startup")
def startup_event():
    init_db()

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...)
):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Invalid input. Only PNG images are allowed for the profile photo.")
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT EXISTS(SELECT 1 FROM profiles WHERE username=?)", (username,))
    
    if cursor.fetchone()[0]:
        conn.close()
        raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")

    try:
        profile_image_bytes = await profile_photo.read()
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail="Error processing profile photo upload")

    try:
        cursor.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
            (username, profile_page, profile_image_bytes)
        )
        conn.commit()
    except sqlite3.Error as e:
        raise HTTPException(status_code=403, detail="Database error")
    finally:
        conn.close()

    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT profile_page FROM profiles WHERE username=?", (username,))
    result = cursor.fetchone()
    
    if not result:
        conn.close()
        raise HTTPException(status_code=404, detail="Profile not found")
    
    conn.close()
    return HTMLResponse(content=result[0])

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT profile_photo FROM profiles WHERE username=?", (username,))
    result = cursor.fetchone()
    
    if not result:
        conn.close()
        raise HTTPException(status_code=404, detail="Profile photo not found")
        
    photo_bytes = result[0]
    conn.close()
    
    # Store image in a temp file to return
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_file.write(photo_bytes)
    temp_file.close()
    
    return FileResponse(temp_file.name, media_type="image/png", headers={"Content-Disposition": f"inline; filename={username}.png"})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)