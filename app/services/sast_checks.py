"""
Static pattern checks that scan Python source for dangerous coding patterns.
These are heuristic — they flag patterns worth reviewing, not confirmed bugs.
"""
import ast
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SASTFinding:
    file: str
    line: int
    pattern: str
    detail: str
    severity: str
    cwe_id: str


_PATTERNS: list[tuple[str, re.Pattern, str, str, str]] = [
    (
        "SQL_INJECTION_FSTRING",
        re.compile(r'f["\'].*\bSELECT\b.*\{', re.IGNORECASE),
        "f-string used in SQL query — potential SQL injection",
        "high",
        "CWE-89",
    ),
    (
        "SQL_INJECTION_FORMAT",
        re.compile(r'["\']\s*SELECT.*%[sd]|["\']\s*SELECT.*\.format\(', re.IGNORECASE),
        "% or .format() used in SQL query — potential SQL injection",
        "high",
        "CWE-89",
    ),
    (
        "HARDCODED_SECRET",
        re.compile(r'(password|secret|token|api_key)\s*=\s*["\'][^"\']{4,}["\']', re.IGNORECASE),
        "Hardcoded credential or secret detected",
        "high",
        "CWE-798",
    ),
    (
        "WEAK_PASSWORD_HASH",
        re.compile(r'hashlib\.(md5|sha1)\s*\(', re.IGNORECASE),
        "MD5/SHA1 used for hashing — unsuitable for passwords (fast, unsalted)",
        "high",
        "CWE-916",
    ),
    (
        "SSRF_UNCHECKED_REQUEST",
        re.compile(r'httpx\.(get|post|put|delete|request)\s*\(\s*(?:url|target)', re.IGNORECASE),
        "httpx request with variable URL — verify SSRF guard is applied",
        "medium",
        "CWE-918",
    ),
    (
        "XSS_RAW_HTML",
        re.compile(r'f["\']<[a-z]+>[^"\']*\{[^}]+\}[^"\']*</[a-z]+>["\']', re.IGNORECASE),
        "f-string used to build HTML with interpolated variable — potential XSS",
        "high",
        "CWE-79",
    ),
    (
        "PATH_TRAVERSAL",
        re.compile(r'Path\s*\(\s*\w+\s*\)\s*/\s*file\.filename', re.IGNORECASE),
        "User-controlled filename used in path construction — potential path traversal",
        "high",
        "CWE-22",
    ),
    (
        "JWT_WEAK_OPTIONS",
        re.compile(r'"verify_exp"\s*:\s*False', re.IGNORECASE),
        "JWT expiry verification disabled — authentication bypass risk",
        "critical",
        "CWE-347",
    ),
    (
        "DEBUG_ENDPOINT_ENV_DUMP",
        re.compile(r'os\.environ\.items\(\)', re.IGNORECASE),
        "os.environ.items() in route handler — potential info disclosure",
        "medium",
        "CWE-200",
    ),
    (
        "INSECURE_DESERIALIZATION",
        re.compile(r'(pickle\.loads?|marshal\.loads?|yaml\.load)\s*\(', re.IGNORECASE),
        "Unsafe deserialization (pickle/marshal/yaml.load) — use safe alternatives (yaml.safe_load, json)",
        "high",
        "CWE-502",
    ),
    (
        "OS_COMMAND_INJECTION",
        re.compile(r'(os\.system\s*\(|os\.popen\s*\(|subprocess\.\w+\([^)]*shell\s*=\s*True)', re.IGNORECASE),
        "os.system/os.popen or subprocess with shell=True — potential OS command injection if input is user-controlled",
        "critical",
        "CWE-78",
    ),
    (
        "DISABLED_TLS_VERIFICATION",
        re.compile(r'\bverify\s*=\s*False\b', re.IGNORECASE),
        "TLS certificate verification disabled (verify=False) — enables man-in-the-middle attacks",
        "high",
        "CWE-295",
    ),
]


def scan_file(path: Path) -> list[SASTFinding]:
    findings: list[SASTFinding] = []
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return findings

    lines = source.splitlines()
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for name, pattern, detail, severity, cwe_id in _PATTERNS:
            if pattern.search(line):
                findings.append(
                    SASTFinding(
                        file=str(path),
                        line=lineno,
                        pattern=name,
                        detail=detail,
                        severity=severity,
                        cwe_id=cwe_id,
                    )
                )
    return findings


def scan_directory(root: Path, glob: str = "**/*.py") -> list[SASTFinding]:
    findings: list[SASTFinding] = []
    for path in sorted(root.glob(glob)):
        findings.extend(scan_file(path))
    return findings
