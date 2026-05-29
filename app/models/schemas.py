from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class User(BaseModel):
    user_id: int
    username: str


class Note(BaseModel):
    note_id: int
    user_id: int
    title: str
    content: str


class Comment(BaseModel):
    comment_id: int
    content: str
    rendered_html: str


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class Finding(BaseModel):
    finding_id: str
    title: str
    severity: Literal["low", "medium", "high", "critical"]
    category: str
    owasp_category: str
    cwe_id: str
    affected_endpoint: str
    vulnerable_behavior: str
    secure_behavior: str
    evidence: list[str]
    impact: str
    remediation: str
    test_name: str | None = None
    confidence: Literal["direct", "high", "medium", "low"]


class AppSecReport(BaseModel):
    report_id: str
    generated_at: datetime
    project_name: str
    summary: str
    findings: list[Finding]
    total_findings: int
    severity_counts: dict[str, int]
    limitations: list[str]
