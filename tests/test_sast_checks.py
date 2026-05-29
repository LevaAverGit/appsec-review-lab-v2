import tempfile
from pathlib import Path

import pytest

from app.services.sast_checks import SASTFinding, scan_directory, scan_file


def _write_temp(content: str, suffix: str = ".py") -> Path:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    f.write(content)
    f.close()
    return Path(f.name)


class TestSASTFileScanning:
    def test_sql_injection_fstring_flagged(self):
        p = _write_temp('query = f"SELECT * FROM notes WHERE title LIKE \'%{q}%\'"')
        findings = scan_file(p)
        assert any(f.pattern == "SQL_INJECTION_FSTRING" for f in findings)

    def test_clean_file_no_findings(self):
        p = _write_temp("x = 1 + 2\nprint(x)\n")
        findings = scan_file(p)
        assert len(findings) == 0

    def test_hardcoded_secret_flagged(self):
        p = _write_temp('_WEAK_SECRET = "mysecretpassword"')
        findings = scan_file(p)
        assert any(f.pattern == "HARDCODED_SECRET" for f in findings)

    def test_jwt_verify_exp_false_flagged(self):
        p = _write_temp('options={"verify_exp": False}')
        findings = scan_file(p)
        assert any(f.pattern == "JWT_WEAK_OPTIONS" for f in findings)

    def test_os_environ_items_flagged(self):
        p = _write_temp("env = {k: v for k, v in os.environ.items()}")
        findings = scan_file(p)
        assert any(f.pattern == "DEBUG_ENDPOINT_ENV_DUMP" for f in findings)

    def test_xss_fstring_html_flagged(self):
        p = _write_temp('rendered = f"<p>{content}</p>"')
        findings = scan_file(p)
        assert any(f.pattern == "XSS_RAW_HTML" for f in findings)

    def test_comment_line_skipped(self):
        p = _write_temp('# rendered = f"<p>{content}</p>"')
        findings = scan_file(p)
        xss = [f for f in findings if f.pattern == "XSS_RAW_HTML"]
        assert len(xss) == 0

    def test_finding_has_correct_file_path(self):
        p = _write_temp('options={"verify_exp": False}')
        findings = scan_file(p)
        assert all(f.file == str(p) for f in findings)

    def test_finding_has_line_number(self):
        p = _write_temp('x = 1\noptions = {"verify_exp": False}\ny = 2')
        findings = scan_file(p)
        jwt_findings = [f for f in findings if f.pattern == "JWT_WEAK_OPTIONS"]
        assert len(jwt_findings) > 0
        assert jwt_findings[0].line == 2

    def test_finding_severity_is_set(self):
        p = _write_temp('secret = "hardcoded_value"')
        findings = scan_file(p)
        for f in findings:
            assert f.severity in ("low", "medium", "high", "critical")

    def test_finding_cwe_id_format(self):
        p = _write_temp('options={"verify_exp": False}')
        findings = scan_file(p)
        for f in findings:
            assert f.cwe_id.startswith("CWE-")

    def test_scan_directory_finds_multiple_files(self, tmp_path: Path):
        (tmp_path / "a.py").write_text('secret = "hardcoded"')
        (tmp_path / "b.py").write_text('options={"verify_exp": False}')
        findings = scan_directory(tmp_path)
        patterns = {f.pattern for f in findings}
        assert "HARDCODED_SECRET" in patterns
        assert "JWT_WEAK_OPTIONS" in patterns

    def test_scan_directory_ignores_non_python(self, tmp_path: Path):
        (tmp_path / "config.yaml").write_text('secret: "hardcoded"')
        (tmp_path / "app.py").write_text("x = 1")
        findings = scan_directory(tmp_path)
        assert len(findings) == 0

    def test_vulnerable_routes_have_findings(self):
        routes = Path(__file__).parents[1] / "app" / "api" / "routes_vulnerable.py"
        findings = scan_file(routes)
        # Vulnerable file should have multiple flagged patterns
        assert len(findings) >= 3

    def test_secure_routes_fewer_findings(self):
        vuln = Path(__file__).parents[1] / "app" / "api" / "routes_vulnerable.py"
        sec = Path(__file__).parents[1] / "app" / "api" / "routes_secure.py"
        vuln_findings = scan_file(vuln)
        sec_findings = scan_file(sec)
        # Vulnerable file should have more findings than secure file
        assert len(vuln_findings) > len(sec_findings)
