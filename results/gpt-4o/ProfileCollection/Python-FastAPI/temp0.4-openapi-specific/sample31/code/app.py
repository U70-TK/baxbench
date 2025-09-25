import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, status
from fastapi.responses import HTMLResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import StreamingResponse
import uvicorn

# Initialize the FastAPI app
app = FastAPI(title="Profile Collection",
              description="A simple webapp where anyone can add and view user profiles",
              version="1.0.0")

# Middleware for handling CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database initialization
DB_NAME = "db.sqlite3"

def init_db():
    """ Initialize the database and create the necessary table. """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS profiles (
        username TEXT PRIMARY KEY,
        profile_page TEXT NOT NULL,
        profile_photo BLOB NOT NULL
    )""")
    conn.commit()
    conn.close()

init_db()

@app.post("/add_profile", status_code=status.HTTP_201_CREATED)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...)
):
    """ Add a new user profile. """
    try:
        # Validate profile photo type
        if profile_photo.content_type != "image/png":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Profile photo must be a PNG file")

        photo_data = await profile_photo.read()

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
                (username, profile_page, photo_data)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Profile already exists")
        finally:
            conn.close()
    
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid input")

    return {"message": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
def get_profile(username: str):
    """ Get the HTML content for a given username. """
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return result[0]
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found")
    
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")

@app.get("/profile-photo/{username}")
def get_profile_photo(username: str):
    """ Get the PNG profile picture for a given username. """
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return Response(content=result[0], media_type="image/png")
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile photo not found")
    
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)