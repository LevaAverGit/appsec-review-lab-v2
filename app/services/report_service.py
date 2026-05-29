from datetime import datetime, timezone

from app.models.schemas import AppSecReport, Finding

_LAB_FINDINGS: list[Finding] = [
    Finding(
        finding_id="FIND-001",
        title="SQL Injection in Search Endpoint",
        severity="high",
        category="Injection",
        owasp_category="A03:2021 – Injection",
        cwe_id="CWE-89",
        affected_endpoint="GET /vulnerable/search?q=",
        vulnerable_behavior="User input interpolated into SQL query via f-string. "
        "Attacker can modify query logic, dump tables, or bypass filters.",
        secure_behavior="Parameterized query with ? placeholder. "
        "Input is never interpreted as SQL.",
        evidence=[
            "Query: f\"SELECT ... WHERE title LIKE '%{q}%'\"",
            "Payload ' OR '1'='1 returns all rows",
            "Payload ' UNION SELECT id,username,password_hash FROM users -- dumps credentials",
        ],
        impact="Full database read access; potential data exfiltration of all notes and user credentials.",
        remediation="Use parameterized queries: conn.execute('... WHERE title LIKE ?', (f'%{q}%',))",
        test_name="test_sql_injection.py::TestSQLInjection",
        confidence="direct",
    ),
    Finding(
        finding_id="FIND-002",
        title="Insecure Direct Object Reference (IDOR) on Note Access",
        severity="high",
        category="Broken Access Control",
        owasp_category="A01:2021 – Broken Access Control",
        cwe_id="CWE-639",
        affected_endpoint="GET /vulnerable/notes/{note_id}?user_id=",
        vulnerable_behavior="user_id taken from query parameter, not from authenticated token. "
        "Any caller can read any note by supplying any user_id.",
        secure_behavior="user_id extracted from validated JWT. "
        "Query enforces AND user_id = ? ownership check.",
        evidence=[
            "GET /vulnerable/notes/3?user_id=1 returns bob's note as alice",
            "No token required on vulnerable endpoint",
        ],
        impact="Any authenticated or unauthenticated user can read all notes in the database.",
        remediation="Extract user identity from JWT payload, never from request parameters. "
        "Enforce ownership with AND user_id = ? in query.",
        test_name="test_idor.py::TestIDOR",
        confidence="direct",
    ),
    Finding(
        finding_id="FIND-003",
        title="Weak JWT — Hardcoded Secret and No Expiry Enforcement",
        severity="critical",
        category="Identification and Authentication Failures",
        owasp_category="A07:2021 – Identification and Authentication Failures",
        cwe_id="CWE-287",
        affected_endpoint="POST /vulnerable/login, GET /vulnerable/me",
        vulnerable_behavior="Token signed with hardcoded string 'secret'. "
        "Expiry verification disabled. Attacker can forge tokens or replay stale tokens.",
        secure_behavior="Token signed with long random secret from config. "
        "Short expiry (30 min) enforced on every request.",
        evidence=[
            "jwt.encode({...}, 'secret', algorithm='HS256') used in login",
            "options={'verify_exp': False} in decode — expiry never checked",
            "Forged token with any payload accepted by /vulnerable/me",
        ],
        impact="Authentication bypass. Attacker can impersonate any user by forging a token.",
        remediation="Generate secret with secrets.token_hex(32). "
        "Always include exp claim and let jose enforce it by default.",
        test_name="test_jwt.py::TestJWT",
        confidence="direct",
    ),
    Finding(
        finding_id="FIND-004",
        title="Server-Side Request Forgery (SSRF) in Fetch Endpoint",
        severity="high",
        category="Server-Side Request Forgery",
        owasp_category="A10:2021 – Server-Side Request Forgery",
        cwe_id="CWE-918",
        affected_endpoint="GET /vulnerable/fetch?url=",
        vulnerable_behavior="httpx.get(url) called without any host or scheme validation. "
        "Attacker can reach internal services, metadata endpoints, or loopback interfaces.",
        secure_behavior="URL validated before request: scheme must be http/https, "
        "resolved IP must not be private, loopback, or link-local.",
        evidence=[
            "httpx.get(url, timeout=5) with no guards",
            "GET /vulnerable/fetch?url=http://127.0.0.1/admin reaches localhost",
            "GET /vulnerable/fetch?url=file:///etc/passwd would read local files",
        ],
        impact="Internal network scanning, cloud metadata access (AWS IMDSv1), "
        "or reading local files via file:// scheme.",
        remediation="Resolve hostname to IP, check against RFC1918/loopback/link-local ranges. "
        "Allowlist expected external hostnames when possible.",
        test_name="test_ssrf.py::TestSSRF",
        confidence="direct",
    ),
    Finding(
        finding_id="FIND-005",
        title="Stored Cross-Site Scripting (XSS) in Comments",
        severity="high",
        category="Injection",
        owasp_category="A03:2021 – Injection",
        cwe_id="CWE-79",
        affected_endpoint="POST /vulnerable/comments, GET /vulnerable/comments/rendered",
        vulnerable_behavior="User input stored as raw HTML: f'<p>{content}</p>'. "
        "Script tags and event handlers rendered in the browser.",
        secure_behavior="html.escape(content) applied before constructing HTML. "
        "CSP header added to rendered response.",
        evidence=[
            "Payload <script>alert('xss')</script> stored unescaped",
            "GET /vulnerable/comments/rendered returns <script>alert('xss')</script> in body",
        ],
        impact="Session hijacking, credential theft, malicious redirects for all users "
        "who view the comments page.",
        remediation="Always escape user content with html.escape() before inserting into HTML. "
        "Add Content-Security-Policy header. Consider a templating engine with auto-escaping.",
        test_name="test_xss.py::TestXSS",
        confidence="direct",
    ),
    Finding(
        finding_id="FIND-006",
        title="Insecure File Upload — Missing Extension Check and Path Traversal",
        severity="high",
        category="Security Misconfiguration",
        owasp_category="A05:2021 – Security Misconfiguration",
        cwe_id="CWE-434",
        affected_endpoint="POST /vulnerable/upload",
        vulnerable_behavior="No file extension validation. Original filename used for stored path. "
        "Attacker can upload .php files or use path traversal (../../etc/passwd).",
        secure_behavior="Extension whitelist enforced. Stored filename is a UUID. "
        "Size limit checked. No original filename used in filesystem path.",
        evidence=[
            "shell.php accepted and stored at upload_dir/shell.php",
            "../../etc/passwd used as stored path on vulnerable endpoint",
        ],
        impact="Remote code execution if web server executes uploaded scripts. "
        "Overwrite of arbitrary files via path traversal.",
        remediation="Enforce extension whitelist. Generate UUID-based stored name. "
        "Check file size. Consider validating magic bytes, not just extension.",
        test_name="test_file_upload.py::TestFileUpload",
        confidence="direct",
    ),
    Finding(
        finding_id="FIND-007",
        title="Security Misconfiguration — Debug Endpoint Exposes Secrets",
        severity="high",
        category="Security Misconfiguration",
        owasp_category="A05:2021 – Security Misconfiguration",
        cwe_id="CWE-200",
        affected_endpoint="GET /vulnerable/debug",
        vulnerable_behavior="Debug endpoint returns all environment variables, "
        "JWT secret, DB path, and Python executable path in JSON response.",
        secure_behavior="Debug endpoint returns HTTP 404.",
        evidence=[
            "GET /vulnerable/debug returns jwt_secret in plaintext",
            "Environment variables including PATH and PYTHONPATH exposed",
        ],
        impact="Full secret disclosure. Attacker gains JWT signing key, enabling auth bypass. "
        "Internal config reveals attack surface.",
        remediation="Remove debug endpoints before any deployment. "
        "Never expose env vars or secrets via API. Use structured logging to safe sinks.",
        test_name="test_security_misc.py::TestSecurityMisc",
        confidence="direct",
    ),
]

_LAB_LIMITATIONS = [
    "All vulnerabilities are demonstrated against synthetic in-process data only.",
    "SSRF checks test URL validation logic — no actual outbound requests to external hosts.",
    "File upload tests use in-memory uploads; no real malicious code is executed.",
    "Detection patterns in sast_checks.py are heuristic and may produce false positives.",
    "This is a controlled lab, not a comprehensive scanner or a production security tool.",
]


def build_lab_report() -> AppSecReport:
    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in _LAB_FINDINGS:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    return AppSecReport(
        report_id="RPT-2026-001",
        generated_at=datetime.now(timezone.utc),
        project_name="appsec-review-lab",
        summary=(
            f"{len(_LAB_FINDINGS)} findings documented across 7 vulnerability categories. "
            "Each finding has a vulnerable endpoint, a secure counterpart, evidence, and remediation. "
            "All tests run against an in-process lab application."
        ),
        findings=_LAB_FINDINGS,
        total_findings=len(_LAB_FINDINGS),
        severity_counts=severity_counts,
        limitations=_LAB_LIMITATIONS,
    )


def generate_markdown_report(report: AppSecReport) -> str:
    lines: list[str] = []
    lines.append(f"# AppSec Review Lab — Findings Report")
    lines.append(f"\nReport ID: {report.report_id}")
    lines.append(f"Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"Project: {report.project_name}")
    lines.append("\n---\n")

    lines.append("## Executive Summary\n")
    lines.append(report.summary)
    lines.append("")

    lines.append("## Severity Breakdown\n")
    for sev in ("critical", "high", "medium", "low"):
        count = report.severity_counts.get(sev, 0)
        lines.append(f"- **{sev.upper()}**: {count}")
    lines.append("")

    lines.append("---\n")
    lines.append("## Findings\n")

    for finding in report.findings:
        lines.append(f"### {finding.finding_id} — {finding.title}\n")
        lines.append(f"- **Severity:** {finding.severity.upper()}")
        lines.append(f"- **OWASP:** {finding.owasp_category}")
        lines.append(f"- **CWE:** {finding.cwe_id}")
        lines.append(f"- **Endpoint:** `{finding.affected_endpoint}`")
        lines.append(f"- **Confidence:** {finding.confidence}")
        lines.append("")
        lines.append(f"**Vulnerable behavior:** {finding.vulnerable_behavior}")
        lines.append("")
        lines.append(f"**Secure behavior:** {finding.secure_behavior}")
        lines.append("")
        lines.append("**Evidence:**")
        for ev in finding.evidence:
            lines.append(f"- {ev}")
        lines.append("")
        lines.append(f"**Impact:** {finding.impact}")
        lines.append("")
        lines.append(f"**Remediation:** {finding.remediation}")
        if finding.test_name:
            lines.append(f"\n_Test coverage: `{finding.test_name}`_")
        lines.append("\n---\n")

    lines.append("## Limitations\n")
    for lim in report.limitations:
        lines.append(f"- {lim}")
    lines.append("")

    return "\n".join(lines)
