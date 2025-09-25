import os
import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile, Form
from fastapi.responses import HTMLResponse
from starlette.responses import StreamingResponse
from starlette.middleware.cors import CORSMiddleware
from typing import Annotated
from pydantic import BaseModel
from io import BytesIO

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

# Database connection and initialization
def get_db_connection():
    conn = sqlite3.connect('db.sqlite3')
    return conn

def initialize_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS profiles (
                        username TEXT PRIMARY KEY,
                        profile_page TEXT,
                        profile_photo BLOB
                      )''')
    conn.commit()
    conn.close()

initialize_db()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def sanitize_sql_input(val: str) -> str:
    """Simple sanitation of SQL input to prevent SQL injection."""
    return val.replace("'", "''")  # Escape single quotes

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: Annotated[str, Form()],
    profile_page: Annotated[str, Form()],
    profile_photo: UploadFile
):
    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=400, detail="Invalid photo format. Only PNG is allowed.")

    conn = get_db_connection()
    cursor = conn.cursor()

    # Sanitize and validate input
    esc_username = sanitize_sql_input(username)
    try:
        cursor.execute('SELECT COUNT(*) FROM profiles WHERE username=?', (esc_username,))
        if cursor.fetchone()[0] > 0:
            raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden.")
        
        photo_data = await profile_photo.read()
        cursor.execute('INSERT INTO profiles (username, profile_page, profile_photo) VALUES (?,?,?)',
                       (esc_username, profile_page, sqlite3.Binary(photo_data)))
        conn.commit()
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid input or database error.")
    finally:
        conn.close()

    return {"detail": "Profile created successfully"}

@app.get("/profile/{username}", response_class=HTMLResponse)
async def get_profile(username: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    esc_username = sanitize_sql_input(username)

    try:
        cursor.execute('SELECT profile_page FROM profiles WHERE username=?', (esc_username,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Profile not found")
        
        return HTMLResponse(content=row[0], status_code=200)
    except Exception as e:
        raise HTTPException(status_code=404, detail="Profile not found or database error.")
    finally:
        conn.close()

@app.get("/profile-photo/{username}")
async def get_profile_photo(username: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    esc_username = sanitize_sql_input(username)

    try:
        cursor.execute('SELECT profile_photo FROM profiles WHERE username=?', (esc_username,))
        row = cursor.fetchone()
        if not row or not row[0]:
            raise HTTPException(status_code=404, detail="Profile photo not found")
        
        return StreamingResponse(BytesIO(row[0]), media_type="image/png")
    except Exception as e:
        raise HTTPException(status_code=404, detail="Profile photo not found or database error.")
    finally:
        conn.close()