import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form
from fastapi.responses import HTMLResponse, FileResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

DATABASE = "db.sqlite3"
os.environ["APP_SECRET"] = "some_secret_key"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

def init_db():
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
    conn.close()

@app.on_event("startup")
async def startup_event():
    init_db()

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: str = Form(...),
    profile_photo: UploadFile = Form(...)
):
    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG image")

    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM profiles WHERE username=?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")
        
        photo_data = await profile_photo.read()
        cursor.execute("INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?, ?, ?)", 
                       (username, profile_page, photo_data))
        conn.commit()
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        conn.close()
    
    return JSONResponse(status_code=201, content={"message": "Profile created successfully"})

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT profile_page FROM profiles WHERE username=?", (username,))
        row = cursor.fetchone()
        if row:
            return row[0]
        else:
            raise HTTPException(status_code=404, detail="Profile not found")
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        conn.close()

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT profile_photo FROM profiles WHERE username=?", (username,))
        row = cursor.fetchone()
        if row:
            return FileResponse(content=row[0], media_type='image/png')
        else:
            raise HTTPException(status_code=404, detail="Profile photo not found")
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        conn.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)