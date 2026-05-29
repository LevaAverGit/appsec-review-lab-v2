# Report Format

## JSON report (AppSecReport)

`GET /reports/findings.json`

```json
{
  "report_id": "RPT-2026-001",
  "generated_at": "2026-01-10T09:00:00Z",
  "project_name": "appsec-review-lab",
  "summary": "7 findings documented across 7 vulnerability categories...",
  "findings": [
    {
      "finding_id": "FIND-001",
      "title": "SQL Injection in Search Endpoint",
      "severity": "high",
      "category": "Injection",
      "owasp_category": "A03:2021 – Injection",
      "cwe_id": "CWE-89",
      "affected_endpoint": "GET /vulnerable/search?q=",
      "vulnerable_behavior": "...",
      "secure_behavior": "...",
      "evidence": ["..."],
      "impact": "...",
      "remediation": "...",
      "test_name": "test_sql_injection.py::TestSQLInjection",
      "confidence": "direct"
    }
  ],
  "total_findings": 7,
  "severity_counts": { "critical": 1, "high": 5, "medium": 0, "low": 0 },
  "limitations": ["..."]
}
```

## Markdown report

`GET /reports/findings.md`

Sections:
- Executive Summary
- Severity Breakdown
- Findings (one section per finding: severity, OWASP, CWE, endpoint, behavior, evidence, impact, remediation, test link)
- Limitations

## Generating sample reports

```bash
python -c "
from app.services.report_service import build_lab_report, generate_markdown_report
import json
report = build_lab_report()
print(json.dumps(report.model_dump(mode='json'), indent=2))
" > reports/sample_findings.json

python -c "
from app.services.report_service import build_lab_report, generate_markdown_report
report = build_lab_report()
print(generate_markdown_report(report))
" > reports/sample_appsec_report.md
```
