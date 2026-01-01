"""DocScope API - Document forensics analysis service."""

import os
import time
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from models.response import AnalysisResponse, Summary, Finding
from analyzers.common import MAX_FILE_SIZE, ALLOWED_EXTENSIONS

# Initialize FastAPI app
app = FastAPI(
    title="DocScope API",
    description="Document forensics API that scans PDF and DOCX files for hidden content and security threats",
    version="1.0.0"
)

# Configure CORS middleware (allow all origins for development)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure temp directory exists on startup
TEMP_DIR = Path(__file__).parent / "temp"
TEMP_DIR.mkdir(exist_ok=True)


@app.on_event("startup")
async def startup_event():
    """Create necessary directories on application startup."""
    TEMP_DIR.mkdir(exist_ok=True)
    print(f"✓ Temp directory ready: {TEMP_DIR}")


@app.get("/api/health")
async def health_check():
    """
    Health check endpoint.

    Returns:
        dict: Status of the API service
    """
    return {"status": "healthy"}


@app.post("/api/analyze", response_model=AnalysisResponse)
async def analyze_document(file: UploadFile = File(...)):
    """
    Analyze a PDF or DOCX document for security threats and hidden content.

    Args:
        file: Uploaded document file

    Returns:
        AnalysisResponse: Complete analysis results

    Raises:
        HTTPException: If file validation fails
    """
    start_time = time.time()

    # Validate file extension
    file_extension = Path(file.filename).suffix.lower()
    if file_extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed extensions: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    # Read file content to check size
    file_content = await file.read()
    file_size = len(file_content)

    # Validate file size
    if file_size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size: {MAX_FILE_SIZE / (1024 * 1024):.0f}MB"
        )

    # Validate file is not empty
    if file_size == 0:
        raise HTTPException(
            status_code=400,
            detail="File is empty"
        )

    # Determine file type
    file_type = "pdf" if file_extension == ".pdf" else "docx"

    # Calculate scan time
    scan_time_ms = int((time.time() - start_time) * 1000)

    # TODO: Add real document analysis here
    # For now, return a mock response with empty findings

    return AnalysisResponse(
        success=True,
        filename=file.filename,
        file_type=file_type,
        file_size=file_size,
        scan_time_ms=scan_time_ms,
        summary=Summary(
            critical=0,
            high=0,
            medium=0,
            low=0,
            total=0
        ),
        findings=[]
    )


# Mount static files directory (if it exists)
STATIC_DIR = Path(__file__).parent.parent / "static"
if STATIC_DIR.exists():
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
