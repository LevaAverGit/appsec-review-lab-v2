import pytest
import httpx

from app.services.dast_checks import (
    DASTResult,
    check_file_upload,
    check_idor,
    check_jwt_weak,
    check_security_misconfiguration,
    check_sql_injection,
    check_ssrf,
    check_xss,
    run_all_checks,
)


class TestDASTChecks:
    def test_sql_injection_check_returns_results(self, client: httpx.Client):
        results = check_sql_injection(client)
        assert len(results) >= 3

    def test_sql_injection_vulnerable_flagged(self, client: httpx.Client):
        results = check_sql_injection(client)
        vuln = [r for r in results if r.endpoint == "/vulnerable/search" and not r.passed]
        assert len(vuln) >= 1

    def test_sql_injection_secure_passes(self, client: httpx.Client):
        results = check_sql_injection(client)
        secure = [r for r in results if r.endpoint == "/secure/search"]
        assert all(r.passed for r in secure)

    def test_idor_check_returns_results(self, client: httpx.Client):
        results = check_idor(client)
        assert len(results) >= 1

    def test_idor_vulnerable_flagged(self, client: httpx.Client):
        results = check_idor(client)
        assert any(not r.passed for r in results)

    def test_jwt_check_returns_results(self, client: httpx.Client):
        results = check_jwt_weak(client)
        assert len(results) >= 2

    def test_jwt_vulnerable_forged_token_accepted(self, client: httpx.Client):
        results = check_jwt_weak(client)
        forged = [r for r in results if r.check_name == "JWT_WEAK_SECRET"]
        assert len(forged) == 1
        assert not forged[0].passed  # vulnerable accepted it

    def test_jwt_secure_rejects_expired(self, client: httpx.Client):
        results = check_jwt_weak(client)
        expiry_check = [r for r in results if r.check_name == "JWT_EXPIRY_ENFORCED"]
        assert len(expiry_check) == 1
        assert expiry_check[0].passed  # secure correctly rejected expired

    def test_ssrf_check_returns_results(self, client: httpx.Client):
        results = check_ssrf(client)
        assert len(results) >= 4

    def test_ssrf_vulnerable_returns_internal(self, client: httpx.Client):
        results = check_ssrf(client)
        vuln = [r for r in results if r.check_name == "SSRF_VULNERABLE_RETURNS_INTERNAL"]
        assert len(vuln) == 1
        # Vulnerable endpoint returns simulated internal content — not passed
        assert not vuln[0].passed

    def test_ssrf_secure_blocks_all(self, client: httpx.Client):
        results = check_ssrf(client)
        secure = [r for r in results if r.check_name == "SSRF_BLOCKED"]
        assert all(r.passed for r in secure)

    def test_xss_check_returns_results(self, client: httpx.Client):
        results = check_xss(client)
        assert len(results) >= 2

    def test_xss_vulnerable_flagged(self, client: httpx.Client):
        results = check_xss(client)
        vuln = [r for r in results if r.check_name == "XSS_STORED_VULNERABLE"]
        assert len(vuln) == 1
        assert not vuln[0].passed  # vulnerable stored script unescaped

    def test_xss_secure_passes(self, client: httpx.Client):
        results = check_xss(client)
        sec = [r for r in results if r.check_name == "XSS_ESCAPED_SECURE"]
        assert len(sec) == 1
        assert sec[0].passed

    def test_file_upload_check_returns_results(self, client: httpx.Client):
        results = check_file_upload(client)
        assert len(results) >= 2

    def test_file_upload_secure_passes(self, client: httpx.Client):
        results = check_file_upload(client)
        assert all(r.passed for r in results)

    def test_security_misc_check_returns_results(self, client: httpx.Client):
        results = check_security_misconfiguration(client)
        assert len(results) >= 2

    def test_security_misc_vulnerable_flagged(self, client: httpx.Client):
        results = check_security_misconfiguration(client)
        debug_exposes = [r for r in results if r.check_name == "DEBUG_EXPOSES_SECRETS"]
        assert len(debug_exposes) == 1
        assert not debug_exposes[0].passed  # vulnerable exposed secrets

    def test_security_misc_secure_debug_disabled(self, client: httpx.Client):
        results = check_security_misconfiguration(client)
        disabled = [r for r in results if r.check_name == "DEBUG_DISABLED_SECURE"]
        assert len(disabled) == 1
        assert disabled[0].passed

    def test_run_all_checks_returns_all_categories(self, client: httpx.Client):
        results = run_all_checks(client)
        check_names = {r.check_name for r in results}
        expected = {
            "SQL_INJECTION", "SQL_INJECTION_SECURE",
            "IDOR",
            "JWT_WEAK_SECRET", "JWT_EXPIRY_ENFORCED",
            "SSRF_VULNERABLE_RETURNS_INTERNAL", "SSRF_BLOCKED",
            "XSS_STORED_VULNERABLE", "XSS_ESCAPED_SECURE",
            "FILE_UPLOAD_EXTENSION_BLOCKED", "FILE_UPLOAD_PATH_TRAVERSAL",
            "DEBUG_EXPOSES_SECRETS", "DEBUG_DISABLED_SECURE",
        }
        assert expected.issubset(check_names)

    def test_dast_result_has_required_fields(self, client: httpx.Client):
        results = run_all_checks(client)
        for r in results:
            assert r.check_name
            assert r.endpoint
            assert r.cwe_id.startswith("CWE-")
            assert r.severity in ("low", "medium", "high", "critical")
