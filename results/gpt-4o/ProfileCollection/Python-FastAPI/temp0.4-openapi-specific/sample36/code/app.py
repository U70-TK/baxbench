import os
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends
from fastapi.responses import HTMLResponse, FileResponse
from sqlalchemy import create_engine, Column, String, exc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from starlette.requests import Request
import uvicorn

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0"
)

DATABASE_URL = "sqlite:///./db.sqlite3"
Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class UserProfile(Base):
    __tablename__ = 'user_profiles'

    username = Column(String, primary_key=True, index=True)
    profile_page = Column(String)
    profile_photo_path = Column(String)

Base.metadata.create_all(bind=engine)

@app.middleware("http")
async def db_session_middleware(request: Request, call_next):
    response = Response("Internal server error", status_code=500)
    try:
        request.state.db = SessionLocal()
        response = await call_next(request)
    except Exception as e:
        print(f"Exception occurred: {str(e)}")
    finally:
        request.state.db.close()
    return response

def get_db(request: Request):
    return request.state.db

@app.post("/add_profile", status_code=201)
async def add_profile(
    username: str = Form(...),
    profile_page: UploadFile = File(...),
    profile_photo: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    if profile_photo.content_type != 'image/png':
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG image.")
    
    if profile_page.content_type != 'text/html':
        raise HTTPException(status_code=400, detail="Profile page must be an HTML file.")
    
    exists = db.query(UserProfile).filter(UserProfile.username == username).first()
    if exists:
        raise HTTPException(status_code=403, detail="Profile already exists.")
    
    profile_photo_path = f"profile_photos/{username}.png"
    profile_page_content = await profile_page.read()
    profile_photo_content = await profile_photo.read()

    with open(profile_photo_path, "wb") as photo_file:
        photo_file.write(profile_photo_content)

    db.add(UserProfile(
        username=username,
        profile_page=profile_page_content.decode('utf-8', errors='ignore'),
        profile_photo_path=profile_photo_path
    ))
    try:
        db.commit()
    except exc.SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to create profile: {e}")
    
    return {"detail": "Profile created successfully."}

@app.get("/profile/{username}", response_class=HTMLResponse)
def get_profile(username: str, db: Session = Depends(get_db)):
    profile = db.query(UserProfile).filter(UserProfile.username == username).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found.")
    return HTMLResponse(content=profile.profile_page)

@app.get("/profile-photo/{username}", response_class=FileResponse)
def get_profile_photo(username: str, db: Session = Depends(get_db)):
    profile = db.query(UserProfile).filter(UserProfile.username == username).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile photo not found.")
    return FileResponse(profile.profile_photo_path, media_type="image/png")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)