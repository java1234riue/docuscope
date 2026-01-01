# DocScope

Document forensics and security scanner. Upload PDF or DOCX files to detect hidden content, security threats, and metadata exposure.

## Features
- Hidden text detection (white text, tiny fonts, zero-width characters)
- Suspicious link analysis
- Metadata exposure scanning
- Embedded threat detection (macros, JavaScript, OLE objects)
- Failed redaction detection

## Tech Stack
- Backend: Python, FastAPI, PyMuPDF, python-docx, oletools
- Frontend: Vanilla HTML/CSS/JS
- Deployment: Render

## Development
```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload

# Access at http://localhost:8000
```

## Privacy
Files are processed in memory and deleted immediately after analysis. No data is stored.