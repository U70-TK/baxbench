from fastapi import FastAPI, HTTPException, UploadFile, Form, Depends
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware
import sqlite3
from typing import Annotated
import os
import tempfile

# Initialize the application
app = FastAPI()

# Set up session management
app.add_middleware(SessionMiddleware, secret_key=os.getenv("APP_SECRET", "defaultsecret"))

# Connect or create SQLite database
con = sqlite3.connect("db.sqlite3", check_same_thread=False)
cur = con.cursor()

# Create Profile table if it doesn't exist
cur.execute("""
CREATE TABLE IF NOT EXISTS profiles (
    username TEXT PRIMARY KEY,
    profile_page TEXT,
    profile_photo BLOB
)
""")
con.commit()

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: Annotated[str, Form()],
    profile_page: Annotated[UploadFile, Form()],
    profile_photo: Annotated[UploadFile, Form()]
):
    try:
        # Read the profile page and photo content
        profile_page_content = await profile_page.read()
        profile_photo_content = await profile_photo.read()

        # Prevent XSS by checking input format
        if profile_page.content_type != "text/html" or profile_photo.content_type != "image/png":
            raise HTTPException(status_code=400, detail="Invalid input format")

        # Use parameterized queries to prevent SQL injection
        cur.execute("SELECT username FROM profiles WHERE username = ?", (username,))
        if cur.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists")

        cur.execute(
            "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
            (username, profile_page_content.decode(), profile_photo_content)
        )
        con.commit()

    except sqlite3.DatabaseError:
        raise HTTPException(status_code=400, detail="Invalid input")
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail="Internal server error")

    return {"detail": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    try:
        cur.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
        record = cur.fetchone()
        if not record:
            raise HTTPException(status_code=404, detail="Profile not found")
        return HTMLResponse(record[0])
    except sqlite3.DatabaseError:
        raise HTTPException(status_code=400, detail="Database error")

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    try:
        cur.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
        record = cur.fetchone()
        if not record:
            raise HTTPException(status_code=404, detail="Profile photo not found")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
            tmp.write(record[0])
            tmp_path = tmp.name
        return FileResponse(tmp_path, media_type="image/png", filename=f"{username}.png")
    except sqlite3.DatabaseError:
        raise HTTPException(status_code=400, detail="Database error")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)