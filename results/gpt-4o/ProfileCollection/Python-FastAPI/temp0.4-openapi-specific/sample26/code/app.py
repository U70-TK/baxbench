import os
import sqlite3
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND
from starlette.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
app_secret = os.getenv("APP_SECRET", "default_secret")

# Initialize FastAPI app
app = FastAPI()

# Add CORS middleware for security
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # This can be adjusted to be more restrictive
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create and configure SQLite database
DB_NAME = "db.sqlite3"
conn = sqlite3.connect(DB_NAME)

def init_db():
    with conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS profiles (
                username TEXT PRIMARY KEY,
                profile_page TEXT NOT NULL,
                profile_photo_path TEXT NOT NULL
            )
        ''')
init_db()

# Serve the static files
os.makedirs("uploads", exist_ok=True)
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")


@app.post("/add_profile", status_code=HTTP_201_CREATED)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = File(...),
):
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Profile photo must be a PNG image")

    photo_path = f"uploads/{username}.png"

    try:
        with conn:
            cur = conn.execute('SELECT 1 FROM profiles WHERE username = ?', (username,))
            if cur.fetchone():
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Profile already exists")

            with open(photo_path, "wb") as f:
                f.write(await profile_photo.read())

            conn.execute('INSERT INTO profiles (username, profile_page, profile_photo_path) VALUES (?, ?, ?)',
                (username, profile_page, photo_path))

    except sqlite3.Error as e:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid input")

    return {"detail": "Profile created successfully"}


@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    try:
        cur = conn.execute('SELECT profile_page FROM profiles WHERE username = ?', (username,))
        row = cur.fetchone()
        if row:
            return row[0]
        else:
            raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile not found")
    except sqlite3.Error as e:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid operation")


@app.get("/profile-photo/{username}", response_class=FileResponse)
async def get_profile_photo(username: str):
    try:
        cur = conn.execute('SELECT profile_photo_path FROM profiles WHERE username = ?', (username,))
        row = cur.fetchone()
        if row:
            return FileResponse(row[0], media_type="image/png")
        else:
            raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Profile photo not found")
    except sqlite3.Error as e:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid operation")


# Run the web server
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)