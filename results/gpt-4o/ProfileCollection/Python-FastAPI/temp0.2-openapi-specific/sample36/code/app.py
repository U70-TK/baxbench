import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form, Depends
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.security import HTTPBearer
from starlette.requests import Request
import uvicorn

# Initialize app
app = FastAPI(title="Profile Collection", version="1.0.0", description="A simple webapp where anyone can add and view user profiles")

# Create database connection
def get_db():
    conn = sqlite3.connect("db.sqlite3")
    conn.row_factory = sqlite3.Row
    return conn

# Reset the database
def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT,
            profile_photo BLOB
        )
    ''')
    conn.commit()
    conn.close()

# Initialize database
init_db()

# Middleware to handle exceptions and clean up database connections
@app.middleware("http")
async def db_session_middleware(request: Request, call_next):
    response = None
    try:
        request.state.db = get_db()
        response = await call_next(request)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        request.state.db.close()
    return response

# Function to sanitize inputs
def sanitize_input(user_input: str) -> str:
    return user_input.replace("<", "&lt;").replace(">", "&gt;")

# Profile creation endpoint
@app.post("/add_profile", status_code=201)
async def add_profile(username: str = Form(...), 
                      profile_page: str = Form(...), 
                      profile_photo: UploadFile = None):
                      
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Invalid profile photo format")
                      
    db = get_db()
    cursor = db.cursor()
    
    # Check if profile already exists
    cursor.execute("SELECT username FROM profiles WHERE username = ?", (username,))
    if cursor.fetchone():
        raise HTTPException(status_code=403, detail="Profile already exists")
    
    sanitized_html_content = sanitize_input(profile_page)
    
    # Save profile
    try:
        photo_data = await profile_photo.read()
        cursor.execute("INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)", 
                       (username, sanitized_html_content, photo_data))
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Invalid input")
    finally:
        db.close()

# Profile retrieval endpoint
@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    result = cursor.fetchone()
    db.close()
	
    if not result:
        raise HTTPException(status_code=404, detail="Profile not found")
    return result["profile_page"]

# Profile photo retrieval endpoint
@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT profile_photo FROM profiles WHERE username = ?", (username,))
    result = cursor.fetchone()
    db.close()

    if not result:
        raise HTTPException(status_code=404, detail="Profile photo not found")
    return StreamingResponse(iter([result["profile_photo"]]), media_type="image/png")

# Entry point for the app
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)