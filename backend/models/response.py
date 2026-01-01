"""Pydantic response models for the DocScope API."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    """A single finding from document analysis."""

    type: str = Field(..., description="Type of finding (e.g., 'hidden_text', 'suspicious_links')")
    subtype: str = Field(..., description="Specific subtype of the finding")
    severity: Severity = Field(..., description="Severity level of the finding")
    description: Optional[str] = Field(None, description="Human-readable description of the finding")
    content: Optional[str] = Field(None, description="Actual content found")
    page: Optional[int] = Field(None, description="Page number where finding was located")
    paragraph: Optional[int] = Field(None, description="Paragraph number where finding was located")
    url: Optional[str] = Field(None, description="URL if finding is link-related")
    field: Optional[str] = Field(None, description="Metadata field name")
    value: Optional[str] = Field(None, description="Metadata field value")


class Summary(BaseModel):
    """Summary of findings by severity level."""

    critical: int = Field(0, description="Number of critical severity findings")
    high: int = Field(0, description="Number of high severity findings")
    medium: int = Field(0, description="Number of medium severity findings")
    low: int = Field(0, description="Number of low severity findings")
    total: int = Field(0, description="Total number of findings")


class AnalysisResponse(BaseModel):
    """Complete response model for document analysis."""

    success: bool = Field(..., description="Whether the analysis completed successfully")
    filename: str = Field(..., description="Name of the analyzed file")
    file_type: str = Field(..., description="Type of file analyzed (pdf or docx)")
    file_size: int = Field(..., description="Size of file in bytes")
    scan_time_ms: int = Field(..., description="Time taken to scan in milliseconds")
    summary: Summary = Field(..., description="Summary of findings by severity")
    findings: list[Finding] = Field(default_factory=list, description="List of all findings")
