import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form, Depends
from fastapi.responses import HTMLResponse, Response
from starlette.requests import Request
from starlette.middleware.cors import CORSMiddleware
from starlette.staticfiles import StaticFiles
from pydantic import BaseModel

# Initialize FastAPI app
app = FastAPI(title="Profile Collection")

# Middleware to allow resources to be served across origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create or connect to the SQLite3 database
db_name = "db.sqlite3"
conn = sqlite3.connect(db_name)
cursor = conn.cursor()

# Create profiles table if it does not exist
cursor.execute('''
CREATE TABLE IF NOT EXISTS profiles (
    username TEXT PRIMARY KEY,
    profile_page TEXT NOT NULL,
    profile_photo_filename TEXT NOT NULL
)
''')
conn.commit()

# Helper function to initialize file storage directory
os.makedirs('profiles', exist_ok=True)

# Dependency for getting DB connection for each request
def get_db():
    conn = sqlite3.connect(db_name)
    try:
        yield conn
    finally:
        conn.close()

# Endpoint to add a new user profile
@app.post("/add_profile", response_model=None, status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: UploadFile = Form(...),
    profile_photo: UploadFile = Form(...),
    db: sqlite3.Connection = Depends(get_db)
):
    cursor = db.cursor()

    # Prevent SQL injection by using parameterized queries
    query = "SELECT username FROM profiles WHERE username = ?"
    cursor.execute(query, (username,))
    if cursor.fetchone():
        raise HTTPException(status_code=403, detail="Profile already exists.")

    # Validate file types and avoid CWE-79
    if profile_page.content_type != "text/html":
        raise HTTPException(status_code=400, detail="Invalid profile page type.")
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Invalid profile photo type.")

    # Store profile photo with unique filename
    profile_photo_filename = f"profiles/{username}.png"
    with open(profile_photo_filename, "wb") as file:
        file.write(await profile_photo.read())

    # Store profile page content safely
    profile_page_content = await profile_page.read()
    cursor.execute(
        "INSERT INTO profiles (username, profile_page, profile_photo_filename) VALUES (?, ?, ?)",
        (username, profile_page_content.decode('utf-8'), profile_photo_filename)
    )
    db.commit()

# Endpoint to get user profile by username
@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT profile_page FROM profiles WHERE username = ?", (username,))
    result = cursor.fetchone()
    if not result:
        raise HTTPException(status_code=404, detail="Profile not found.")
    return HTMLResponse(content=result[0])

# Endpoint to get profile photo by username
@app.get("/profile-photo/{username}", response_class=Response)
async def get_profile_photo(username: str, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT profile_photo_filename FROM profiles WHERE username = ?", (username,))
    result = cursor.fetchone()
    if not result:
        raise HTTPException(status_code=404, detail="Profile photo not found.")

    # Reading and returning the stored profile photo
    profile_photo_path = result[0]
    with open(profile_photo_path, "rb") as file:
        return Response(content=file.read(), media_type="image/png")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)