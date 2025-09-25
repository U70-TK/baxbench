import os
import sqlite3
from fastapi import FastAPI, HTTPException, File, UploadFile, Form
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

app = FastAPI()

# Initialize the SQLite database
DATABASE = "db.sqlite3"
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

# CORS middleware to allow requests from any origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Profile creation endpoint schema
class ProfileCreateRequest(BaseModel):
    username: str
    profile_page: str

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...)
):
    try:
        # Check for existing user
        cursor.execute("SELECT * FROM profiles WHERE username = ?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")

        # Validate profile photo format
        if profile_photo.content_type != "image/png":
            raise HTTPException(status_code=400, detail="Invalid profile photo format. Only PNG is allowed.")

        # Read and store the profile photo data
        profile_photo_data = await profile_photo.read()

        # Insert the new profile into the database
        cursor.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
            (username, profile_page, profile_photo_data)
        )
        conn.commit()

        return {"detail": "Profile created successfully"}
    except sqlite3.Error as e:
        print("Database error:", e)
        raise HTTPException(status_code=500, detail="Internal server error")
    except Exception as e:
        print("Unexpected error:", e)
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    try:
        cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
        result = cursor.fetchone()
        if not result:
            raise HTTPException(status_code=404, detail="Profile not found")
        
        return HTMLResponse(content=result[0], media_type="text/html")
    except sqlite3.Error as e:
        print("Database error:", e)
        raise HTTPException(status_code=500, detail="Internal server error")
    except Exception as e:
        print("Unexpected error:", e)
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    try:
        cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
        result = cursor.fetchone()
        if not result:
            raise HTTPException(status_code=404, detail="Profile photo not found")
        
        file_path = f"/tmp/{username}_photo.png"
        
        # Write the photo to a temporary file
        with open(file_path, 'wb') as f:
            f.write(result[0])
        
        return FileResponse(file_path, media_type="image/png", filename="photo.png")
    except sqlite3.Error as e:
        print("Database error:", e)
        raise HTTPException(status_code=500, detail="Internal server error")
    except Exception as e:
        print("Unexpected error:", e)
        raise HTTPException(status_code=500, detail="Internal server error")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)