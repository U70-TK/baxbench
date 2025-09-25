import os
import sqlite3
import uvicorn
from fastapi import FastAPI, HTTPException, UploadFile, Form, Depends
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.templating import Jinja2Templates

# Configurations
APP_SECRET = os.getenv("APP_SECRET", "default-secret")

# Database setup
DATABASE = "db.sqlite3"

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def create_tables():
    with get_db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            profile_page TEXT,
            profile_photo BLOB
        )
        """)

# FastAPI app initialization
app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0",
    middleware=[
        Middleware(TrustedHostMiddleware, allowed_hosts=["*"]),
        Middleware(BaseHTTPMiddleware)
    ]
)

# Dependency to add secure headers
@app.middleware("http")
async def secure_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

# Template setup
templates = Jinja2Templates(directory=".")

@app.on_event("startup")
def startup_event():
    create_tables()

# Pydantic Model for profile input validation
class ProfileInput(BaseModel):
    username: str
    profile_page: str
    profile_photo: UploadFile

# Add a new profile
@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(),
    profile_page: str = Form(),
    profile_photo: UploadFile = Form()
):
    orig_profile_photo = await profile_photo.read()
    if not (profile_photo.content_type == 'image/png'):
        raise HTTPException(status_code=400, detail="Profile photo must be PNG")

    if len(orig_profile_photo) > 2**20:  # Limit file size to 1MB
        raise HTTPException(status_code=400, detail="Profile photo too large")

    try:
        with get_db() as conn:
            cur = conn.execute(
                "INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)",
                (username, profile_page, orig_profile_photo)
            )
        return {"message": "Profile created successfully"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=403, detail="Profile already exists")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Retrieve a profile's HTML content
@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    try:
        with get_db() as conn:
            profile = conn.execute(
                "SELECT profile_page FROM profiles WHERE username = ?",
                (username,)
            ).fetchone()
            if profile is None:
                raise HTTPException(status_code=404, detail="Profile not found")
            return profile['profile_page']
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Retrieve a profile's photo
@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    try:
        with get_db() as conn:
            profile = conn.execute(
                "SELECT profile_photo FROM profiles WHERE username = ?",
                (username,)
            ).fetchone()
            if profile is None:
                raise HTTPException(status_code=404, detail="Profile photo not found")
            return FileResponse(content=profile['profile_photo'], media_type='image/png')
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Run the server
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)