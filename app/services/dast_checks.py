"""
Dynamic checks that probe running endpoints with attack payloads via httpx test client.
All checks run only against the in-process test application — never against external targets.
"""
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class DASTResult:
    check_name: str
    endpoint: str
    payload: str
    passed: bool
    detail: str
    severity: str
    cwe_id: str


def check_sql_injection(client: httpx.Client) -> list[DASTResult]:
    results: list[DASTResult] = []
    # Read-only payloads only — no destructive statements
    payloads = [
        ("' OR '1'='1", "tautology injection"),
        ("' UNION SELECT 1, 'test', 'test' --", "UNION read injection"),
        ("' UNION SELECT id,username,password_hash FROM users --", "UNION credential dump"),
    ]
    for payload, label in payloads:
        resp = client.get("/vulnerable/search", params={"q": payload})
        # Injection is confirmed when we get a 200 with data OR a 400 from sqlite error
        # A 400 with sqlite error text also indicates the query was executed unsafely
        vulnerable = resp.status_code == 200 or (
            resp.status_code == 400 and "sqlite" in resp.text.lower()
        )
        results.append(
            DASTResult(
                check_name="SQL_INJECTION",
                endpoint="/vulnerable/search",
                payload=payload,
                passed=not vulnerable,
                detail=f"{label}: status={resp.status_code}",
                severity="high",
                cwe_id="CWE-89",
            )
        )

    # Secure endpoint should not be injectable
    for payload, label in payloads:
        resp = client.get("/secure/search", params={"q": payload})
        safe = resp.status_code == 200
        results.append(
            DASTResult(
                check_name="SQL_INJECTION_SECURE",
                endpoint="/secure/search",
                payload=payload,
                passed=safe,
                detail=f"{label}: status={resp.status_code}",
                severity="high",
                cwe_id="CWE-89",
            )
        )
    return results


def check_idor(client: httpx.Client) -> list[DASTResult]:
    results: list[DASTResult] = []
    # Note ID 3 belongs to user 2 (bob), but requesting as user_id=1 (alice) succeeds on vulnerable
    resp = client.get("/vulnerable/notes/3", params={"user_id": 1})
    vulnerable = resp.status_code == 200
    results.append(
        DASTResult(
            check_name="IDOR",
            endpoint="/vulnerable/notes/3",
            payload="user_id=1 (accessing bob's note as alice)",
            passed=not vulnerable,
            detail=f"status={resp.status_code}, got data={resp.status_code == 200}",
            severity="high",
            cwe_id="CWE-639",
        )
    )
    return results


def check_jwt_weak(client: httpx.Client) -> list[DASTResult]:
    results: list[DASTResult] = []
    import time
    from jose import jwt

    # Forge a token with weak secret
    forged = jwt.encode({"sub": "999", "username": "attacker"}, "secret", algorithm="HS256")
    resp = client.get("/vulnerable/me", headers={"Authorization": f"Bearer {forged}"})
    vulnerable = resp.status_code == 200
    results.append(
        DASTResult(
            check_name="JWT_WEAK_SECRET",
            endpoint="/vulnerable/me",
            payload="token signed with 'secret'",
            passed=not vulnerable,
            detail=f"Forged token accepted: {resp.status_code == 200}",
            severity="critical",
            cwe_id="CWE-287",
        )
    )

    # Expired token should be rejected on secure endpoint
    exp_past = int(time.time()) - 3600
    expired_token = jwt.encode(
        {"sub": "1", "username": "alice", "exp": exp_past},
        "FAKE_JWT_SECRET_FOR_LAB_ONLY_NOT_FOR_PRODUCTION",
        algorithm="HS256",
    )
    resp2 = client.get("/secure/me", headers={"Authorization": f"Bearer {expired_token}"})
    secure_rejects_expired = resp2.status_code == 401
    results.append(
        DASTResult(
            check_name="JWT_EXPIRY_ENFORCED",
            endpoint="/secure/me",
            payload="expired token",
            passed=secure_rejects_expired,
            detail=f"Expired token rejected: {secure_rejects_expired}",
            severity="critical",
            cwe_id="CWE-347",
        )
    )
    return results


def check_ssrf(client: httpx.Client) -> list[DASTResult]:
    results: list[DASTResult] = []

    # Vulnerable endpoint returns simulated internal content for lab demo URLs
    # (no real HTTP request is made — demonstrates the SSRF concept safely)
    demo_url = "http://127.0.0.1/admin"
    resp_vuln = client.get("/vulnerable/fetch", params={"url": demo_url})
    vuln_returns_internal = (
        resp_vuln.status_code == 200 and "LAB SIMULATION" in resp_vuln.text
    )
    results.append(
        DASTResult(
            check_name="SSRF_VULNERABLE_RETURNS_INTERNAL",
            endpoint="/vulnerable/fetch",
            payload=demo_url,
            passed=not vuln_returns_internal,
            detail=f"Simulated internal content returned: {vuln_returns_internal}",
            severity="high",
            cwe_id="CWE-918",
        )
    )

    # Secure endpoint blocks the same lab demo URLs
    blocked_urls = [
        "http://127.0.0.1/admin",
        "http://localhost/",
        "http://192.168.1.1/router",
        "file:///etc/passwd",
    ]
    for url in blocked_urls:
        resp = client.get("/secure/fetch", params={"url": url})
        blocked = resp.status_code == 400
        results.append(
            DASTResult(
                check_name="SSRF_BLOCKED",
                endpoint="/secure/fetch",
                payload=url,
                passed=blocked,
                detail=f"Internal URL blocked: {blocked} (status={resp.status_code})",
                severity="high",
                cwe_id="CWE-918",
            )
        )
    return results


def check_xss(client: httpx.Client) -> list[DASTResult]:
    results: list[DASTResult] = []
    xss_payload = "<script>alert('xss')</script>"

    resp_vuln = client.post("/vulnerable/comments", params={"content": xss_payload})
    vuln_stored = resp_vuln.status_code == 200 and "<script>" in (
        resp_vuln.json().get("rendered_html", "")
    )
    results.append(
        DASTResult(
            check_name="XSS_STORED_VULNERABLE",
            endpoint="/vulnerable/comments",
            payload=xss_payload,
            passed=not vuln_stored,
            detail=f"Script tag stored unescaped: {vuln_stored}",
            severity="high",
            cwe_id="CWE-79",
        )
    )

    resp_sec = client.post("/secure/comments", params={"content": xss_payload})
    sec_escaped = resp_sec.status_code == 200 and "<script>" not in (
        resp_sec.json().get("rendered_html", "")
    )
    results.append(
        DASTResult(
            check_name="XSS_ESCAPED_SECURE",
            endpoint="/secure/comments",
            payload=xss_payload,
            passed=sec_escaped,
            detail=f"Script tag escaped: {sec_escaped}",
            severity="high",
            cwe_id="CWE-79",
        )
    )
    return results


def check_file_upload(client: httpx.Client) -> list[DASTResult]:
    results: list[DASTResult] = []
    import io

    # Malicious extension rejected by secure endpoint
    php_content = b"<?php system($_GET['cmd']); ?>"
    resp = client.post(
        "/secure/upload",
        files={"file": ("shell.php", io.BytesIO(php_content), "application/octet-stream")},
    )
    blocked = resp.status_code == 400
    results.append(
        DASTResult(
            check_name="FILE_UPLOAD_EXTENSION_BLOCKED",
            endpoint="/secure/upload",
            payload="shell.php",
            passed=blocked,
            detail=f"PHP file rejected: {blocked} (status={resp.status_code})",
            severity="high",
            cwe_id="CWE-434",
        )
    )

    # Path traversal filename rejected by secure endpoint
    traversal_content = b"innocent content"
    resp2 = client.post(
        "/secure/upload",
        files={"file": ("../../etc/passwd.txt", io.BytesIO(traversal_content), "text/plain")},
    )
    # Secure endpoint randomizes filename, so traversal is not possible
    if resp2.status_code == 200:
        stored = resp2.json().get("stored_as", "")
        traversal_prevented = "/" not in stored and ".." not in stored
    else:
        traversal_prevented = True
    results.append(
        DASTResult(
            check_name="FILE_UPLOAD_PATH_TRAVERSAL",
            endpoint="/secure/upload",
            payload="../../etc/passwd.txt",
            passed=traversal_prevented,
            detail=f"Path traversal prevented: {traversal_prevented}",
            severity="high",
            cwe_id="CWE-22",
        )
    )
    return results


def check_security_misconfiguration(client: httpx.Client) -> list[DASTResult]:
    results: list[DASTResult] = []

    # Vulnerable debug exposes secrets
    resp = client.get("/vulnerable/debug")
    exposes_secrets = resp.status_code == 200 and "jwt_secret" in resp.text
    results.append(
        DASTResult(
            check_name="DEBUG_EXPOSES_SECRETS",
            endpoint="/vulnerable/debug",
            payload="GET /vulnerable/debug",
            passed=not exposes_secrets,
            detail=f"jwt_secret in response: {exposes_secrets}",
            severity="high",
            cwe_id="CWE-200",
        )
    )

    # Secure debug returns 404
    resp2 = client.get("/secure/debug")
    secure = resp2.status_code == 404
    results.append(
        DASTResult(
            check_name="DEBUG_DISABLED_SECURE",
            endpoint="/secure/debug",
            payload="GET /secure/debug",
            passed=secure,
            detail=f"Debug endpoint returns 404: {secure}",
            severity="medium",
            cwe_id="CWE-200",
        )
    )
    return results


def run_all_checks(client: httpx.Client) -> list[DASTResult]:
    results: list[DASTResult] = []
    results.extend(check_sql_injection(client))
    results.extend(check_idor(client))
    results.extend(check_jwt_weak(client))
    results.extend(check_ssrf(client))
    results.extend(check_xss(client))
    results.extend(check_file_upload(client))
    results.extend(check_security_misconfiguration(client))
    return results
