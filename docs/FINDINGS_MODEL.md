# Findings Data Model

## Finding

```python
class Finding(BaseModel):
    finding_id: str                   # FIND-001 .. FIND-007
    title: str
    severity: Literal["low", "medium", "high", "critical"]
    category: str                     # Short category label
    owasp_category: str               # e.g. "A03:2021 – Injection"
    cwe_id: str                       # e.g. "CWE-89"
    affected_endpoint: str
    vulnerable_behavior: str
    secure_behavior: str
    evidence: list[str]
    impact: str
    remediation: str
    test_name: str | None             # Corresponding test module::class
    confidence: Literal["direct", "high", "medium", "low"]
```

## AppSecReport

```python
class AppSecReport(BaseModel):
    report_id: str
    generated_at: datetime
    project_name: str
    summary: str
    findings: list[Finding]
    total_findings: int
    severity_counts: dict[str, int]   # {"critical": 1, "high": 5, ...}
    limitations: list[str]
```

## Confidence levels

| Level | Meaning |
|---|---|
| `direct` | The vulnerable behavior is unambiguous and directly observable |
| `high` | High confidence based on code review or pattern match |
| `medium` | Plausible risk; depends on deployment context |
| `low` | Indicative finding; requires manual verification |

All lab findings use `direct` confidence since the vulnerable and secure behaviors are both implemented and tested side-by-side.
