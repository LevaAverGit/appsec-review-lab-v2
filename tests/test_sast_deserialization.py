"""Tests for the INSECURE_DESERIALIZATION SAST rule (CWE-502)."""
import tempfile
from pathlib import Path

from app.services.sast_checks import scan_file


def _write_temp(content: str) -> Path:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False)
    f.write(content)
    f.close()
    return Path(f.name)


def test_pickle_loads_flagged():
    p = _write_temp("data = pickle.loads(untrusted_bytes)")
    findings = scan_file(p)
    assert any(f.pattern == "INSECURE_DESERIALIZATION" for f in findings)


def test_yaml_load_flagged():
    p = _write_temp("cfg = yaml.load(open('c.yml'))")
    findings = scan_file(p)
    assert any(f.pattern == "INSECURE_DESERIALIZATION" for f in findings)


def test_marshal_loads_flagged():
    p = _write_temp("obj = marshal.loads(blob)")
    findings = scan_file(p)
    assert any(f.pattern == "INSECURE_DESERIALIZATION" for f in findings)


def test_yaml_safe_load_not_flagged():
    p = _write_temp("cfg = yaml.safe_load(open('c.yml'))")
    findings = scan_file(p)
    assert not any(f.pattern == "INSECURE_DESERIALIZATION" for f in findings)


def test_finding_has_cwe_502():
    p = _write_temp("data = pickle.loads(x)")
    findings = scan_file(p)
    hit = [f for f in findings if f.pattern == "INSECURE_DESERIALIZATION"][0]
    assert hit.cwe_id == "CWE-502"
    assert hit.severity == "high"
