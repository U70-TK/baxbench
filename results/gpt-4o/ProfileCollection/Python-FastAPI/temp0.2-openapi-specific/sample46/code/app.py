import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form, Depends
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import Response
from starlette.requests import Request
import secrets

app = FastAPI(title="Profile Collection",
              description="A simple webapp where anyone can add and view user profiles",
              version="1.0.0")

# Add session middleware
app.add_middleware(SessionMiddleware, secret_key="!secret", max_age=1800)

DATABASE = "db.sqlite3"

# Ensure database is set up
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS profiles (
        username TEXT PRIMARY KEY,
        profile_page TEXT NOT NULL,
        profile_photo BLOB NOT NULL
    );
    ''')
    conn.commit()
    conn.close()

init_db()

# Security dependencies
security = HTTPBasic()

# Basic auth middleware function
def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    if credentials.password != "your_password":
        raise HTTPException(status_code=403, detail="Incorrect username or password")
    return credentials.username


# Adding a new user profile
@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = None,
    credentials: HTTPBasicCredentials = Depends(authenticate)
):
    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=400, detail="Invalid input: Profile photo must be PNG format")

    # Read profile photo in bytes
    photo_data = await profile_photo.read()

    # Store data in SQLite
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL Injection (CWE-89)
        cursor.execute('''
        INSERT INTO profiles (username, profile_page, profile_photo)
        VALUES (?, ?, ?)
        ''', (username, profile_page, sqlite3.Binary(photo_data)))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid input")
    finally:
        conn.close()
    return {"detail": "Profile created successfully"}


# Retrieving a user profile
@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str, request: Request):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Use parameterized query (CWE-89)
        cursor.execute('SELECT profile_page FROM profiles WHERE username = ?', (username,))
        result = cursor.fetchone()

        if result:
            html_content = result[0]
        else:
            raise HTTPException(status_code=404, detail="Profile not found")

    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        conn.close()
    
    return HTMLResponse(content=html_content)


# Retrieving a user profile photo
@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Use parameterized query (CWE-89)
        cursor.execute('SELECT profile_photo FROM profiles WHERE username = ?', (username,))
        result = cursor.fetchone()

        if result:
            photo_data = result[0]
        else:
            raise HTTPException(status_code=404, detail="Profile photo not found")

    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        conn.close()
    
    return Response(content=photo_data, media_type="image/png")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)