"""Common utilities and constants for document analysis."""

from typing import List, Tuple

# Zero-width Unicode characters that may be used to hide content
ZERO_WIDTH_CHARS = [
    '\u200b',  # Zero-width space
    '\u200c',  # Zero-width non-joiner
    '\u200d',  # Zero-width joiner
    '\u2060',  # Word joiner
    '\ufeff',  # Zero-width no-break space
]

# Cyrillic/Latin homograph mappings for detecting homograph attacks
HOMOGRAPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p',
    'с': 'c', 'х': 'x', 'ѕ': 's', 'і': 'i',
    'ј': 'j', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w'
}

# Suspicious VBA macro keywords that may indicate malicious behavior
SUSPICIOUS_MACRO_KEYWORDS = [
    'AutoOpen', 'AutoExec', 'Document_Open',
    'Shell', 'PowerShell', 'WScript',
    'CreateObject', 'Environ', 'DownloadFile'
]

# File upload constraints
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTENSIONS = {'.pdf', '.docx'}


def is_white_color(r: int, g: int, b: int, threshold: int = 250) -> bool:
    """
    Check if RGB color values represent a white or near-white color.

    Args:
        r: Red value (0-255)
        g: Green value (0-255)
        b: Blue value (0-255)
        threshold: Minimum value for each channel to be considered white (default: 250)

    Returns:
        True if all RGB values are above the threshold
    """
    return r >= threshold and g >= threshold and b >= threshold


def is_tiny_font(size: float, threshold: float = 2) -> bool:
    """
    Check if a font size is considered tiny (potentially hidden).

    Args:
        size: Font size in points
        threshold: Maximum size to be considered tiny (default: 2pt)

    Returns:
        True if font size is below the threshold
    """
    return size < threshold


def contains_zero_width(text: str) -> List[Tuple[str, int]]:
    """
    Detect zero-width Unicode characters in text.

    Args:
        text: Text to analyze

    Returns:
        List of tuples containing (character, count) for each zero-width char found
    """
    results = []
    for char in ZERO_WIDTH_CHARS:
        count = text.count(char)
        if count > 0:
            results.append((char, count))
    return results


def check_homograph(text: str) -> List[str]:
    """
    Detect potential homograph attack characters in text.

    Searches for Cyrillic characters that look like Latin characters,
    which could be used in phishing URLs or other deceptive content.

    Args:
        text: Text to analyze (typically a URL or domain name)

    Returns:
        List of suspicious characters found in the text
    """
    suspicious_chars = []
    for char in text:
        if char in HOMOGRAPH_MAP:
            suspicious_chars.append(char)
    return suspicious_chars


def format_file_size(bytes_size: int) -> str:
    """
    Convert file size in bytes to a human-readable string.

    Args:
        bytes_size: File size in bytes

    Returns:
        Human-readable string (e.g., "1.5 MB", "342 KB", "45 bytes")
    """
    if bytes_size < 1024:
        return f"{bytes_size} bytes"
    elif bytes_size < 1024 * 1024:
        kb = bytes_size / 1024
        return f"{kb:.1f} KB"
    elif bytes_size < 1024 * 1024 * 1024:
        mb = bytes_size / (1024 * 1024)
        return f"{mb:.1f} MB"
    else:
        gb = bytes_size / (1024 * 1024 * 1024)
        return f"{gb:.1f} GB"
