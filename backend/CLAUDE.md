# DocScope Backend - AI Development Context

## Project Summary
Document forensics API that scans PDF and DOCX files for hidden content, security threats, and metadata exposure. Returns JSON analysis results.

## Tech Stack
- Python 3.11+
- FastAPI (web framework)
- PyMuPDF / fitz (PDF parsing)
- python-docx (DOCX parsing)
- oletools (macro detection)
- lxml (XML parsing)
- Deployment: Render free tier

## Directory Structure
'''text
backend/
├── main.py                 # FastAPI app, routes, file handling
├── requirements.txt        # Python dependencies
├── analyzers/
│   ├── __init__.py
│   ├── pdf_analyzer.py     # PDF analysis class
│   ├── docx_analyzer.py    # DOCX analysis class
│   └── common.py           # Shared utilities, constants
├── models/
│   ├── __init__.py
│   └── response.py         # Pydantic response models
└── temp/                   # Temporary file storage (gitignored)
'''
## API Specification

### POST /api/analyze
Accepts multipart form data with a single file.

**Constraints:**
- Allowed extensions: .pdf, .docx
- Max file size: 10MB
- File is deleted immediately after analysis

**Response Schema:**
```json
{
    "success": true,
    "filename": "resume.pdf",
    "file_type": "pdf",
    "file_size": 245678,
    "scan_time_ms": 342,
    "summary": {
        "critical": 1,
        "high": 3,
        "medium": 2,
        "low": 5,
        "total": 11
    },
    "findings": [
        {
            "type": "hidden_text",
            "subtype": "white_text",
            "severity": "high",
            "description": "White colored text detected",
            "content": "secret keywords here",
            "page": 1
        }
    ]
}
```

### GET /api/health
Returns: `{"status": "healthy"}`

## Analysis Features to Implement

### PDF Analysis
| Check | Subtype | Severity | Description |
|-------|---------|----------|-------------|
| Hidden Text | white_text | high | Text with color RGB > 250,250,250 |
| Hidden Text | tiny_text | high | Text with font size < 2pt |
| Hidden Text | zero_width_chars | medium | Zero-width Unicode characters |
| Suspicious Links | display_mismatch | high | Display text differs from actual URL |
| Suspicious Links | homograph_attack | critical | Cyrillic/Latin lookalike characters in URL |
| Metadata | author, creator, etc | low | Exposed metadata fields |
| Metadata | file_path_leak | medium | Internal file paths in metadata |
| Embedded Threat | javascript | critical | JavaScript in PDF |
| Embedded Threat | embedded_file | high | Files embedded in PDF |
| Failed Redaction | text_under_rectangle | critical | Text visible under black rectangles |

### DOCX Analysis
| Check | Subtype | Severity | Description |
|-------|---------|----------|-------------|
| Hidden Text | hidden_attribute | high | Text with hidden=True |
| Hidden Text | white_text | high | Text with white font color |
| Hidden Text | tiny_text | high | Text with font size < 2pt |
| Hidden Text | zero_width_chars | medium | Zero-width Unicode characters |
| Suspicious Links | homograph_attack | critical | Cyrillic lookalikes in URLs |
| Metadata | author, company, etc | low-medium | Exposed metadata |
| Embedded Threat | macro_detected | critical | VBA macros present |
| Embedded Threat | suspicious_macro_keyword | critical | Dangerous keywords in macro code |
| Embedded Threat | ole_object | high | Embedded OLE objects |
| Deleted Content | track_changes_deletion | medium | Deleted text in track changes |
| Deleted Content | comment | low | Comments still in document |

## Code Standards
- Use Python type hints on all functions
- Use async for file operations
- Wrap all file operations in try/finally to ensure cleanup
- Each analyzer is a class with a run_all_checks() method
- Return List[dict] from each check function
- Use Pydantic for request/response validation

## Constants (put in common.py)
```python
ZERO_WIDTH_CHARS = [
    '\u200b',  # Zero-width space
    '\u200c',  # Zero-width non-joiner
    '\u200d',  # Zero-width joiner
    '\u2060',  # Word joiner
    '\ufeff',  # Zero-width no-break space
]

HOMOGRAPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 
    'с': 'c', 'х': 'x', 'ѕ': 's', 'і': 'i',
    'ј': 'j', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w'
}

SUSPICIOUS_MACRO_KEYWORDS = [
    'AutoOpen', 'AutoExec', 'Document_Open',
    'Shell', 'PowerShell', 'WScript',
    'CreateObject', 'Environ', 'DownloadFile'
]

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTENSIONS = {'.pdf', '.docx'}
```