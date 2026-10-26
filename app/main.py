
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router

app = FastAPI(
    title="RDRS API",
    description="Sandbox-only Ransomware Detection and Response System",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5501",
        "http://localhost:5501",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)


app.include_router(router)


@app.get("/")
def root():
    return {
        "name": "RDRS",
        "message": "RDRS API is running",
        "docs": "/docs",
    }
