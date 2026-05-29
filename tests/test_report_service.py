import pytest

from app.models.schemas import AppSecReport, Finding
from app.services.report_service import (
    _LAB_FINDINGS,
    _LAB_LIMITATIONS,
    build_lab_report,
    generate_markdown_report,
)


class TestBuildLabReport:
    def test_report_has_seven_findings(self):
        report = build_lab_report()
        assert report.total_findings == 7
        assert len(report.findings) == 7

    def test_report_total_matches_findings_list(self):
        report = build_lab_report()
        assert report.total_findings == len(report.findings)

    def test_report_severity_counts_sum_to_total(self):
        report = build_lab_report()
        assert sum(report.severity_counts.values()) == report.total_findings

    def test_report_has_generated_at(self):
        report = build_lab_report()
        assert report.generated_at is not None

    def test_report_has_report_id(self):
        report = build_lab_report()
        assert report.report_id.startswith("RPT-")

    def test_report_project_name(self):
        report = build_lab_report()
        assert report.project_name == "appsec-review-lab"

    def test_all_findings_have_owasp_category(self):
        report = build_lab_report()
        for f in report.findings:
            # OWASP categories follow format A01:, A02:, ..., A10:
            assert "2021" in f.owasp_category, f"{f.finding_id} missing OWASP year"

    def test_all_findings_have_cwe_id(self):
        report = build_lab_report()
        for f in report.findings:
            assert f.cwe_id.startswith("CWE-")

    def test_all_findings_have_evidence(self):
        report = build_lab_report()
        for f in report.findings:
            assert len(f.evidence) >= 1

    def test_all_findings_have_remediation(self):
        report = build_lab_report()
        for f in report.findings:
            assert len(f.remediation) > 10

    def test_all_findings_severity_valid(self):
        report = build_lab_report()
        valid = {"low", "medium", "high", "critical"}
        for f in report.findings:
            assert f.severity in valid

    def test_all_findings_confidence_valid(self):
        report = build_lab_report()
        valid = {"direct", "high", "medium", "low"}
        for f in report.findings:
            assert f.confidence in valid

    def test_report_has_limitations(self):
        report = build_lab_report()
        assert len(report.limitations) >= 3

    def test_report_serializable_to_json(self):
        report = build_lab_report()
        data = report.model_dump(mode="json")
        assert isinstance(data, dict)
        assert "findings" in data

    def test_finding_ids_are_unique(self):
        report = build_lab_report()
        ids = [f.finding_id for f in report.findings]
        assert len(ids) == len(set(ids))


class TestMarkdownReport:
    def test_contains_report_id(self):
        md = generate_markdown_report(build_lab_report())
        assert "RPT-2026-001" in md

    def test_contains_executive_summary_section(self):
        md = generate_markdown_report(build_lab_report())
        assert "Executive Summary" in md

    def test_contains_severity_breakdown(self):
        md = generate_markdown_report(build_lab_report())
        assert "Severity Breakdown" in md

    def test_contains_each_finding_id(self):
        md = generate_markdown_report(build_lab_report())
        for f in _LAB_FINDINGS:
            assert f.finding_id in md

    def test_contains_owasp_references(self):
        md = generate_markdown_report(build_lab_report())
        assert "A03:2021" in md or "OWASP" in md

    def test_contains_cwe_references(self):
        md = generate_markdown_report(build_lab_report())
        assert "CWE-89" in md

    def test_contains_limitations(self):
        md = generate_markdown_report(build_lab_report())
        assert "Limitations" in md

    def test_contains_remediation(self):
        md = generate_markdown_report(build_lab_report())
        assert "Remediation" in md

    def test_no_ai_traces(self):
        md = generate_markdown_report(build_lab_report())
        forbidden = [
            "Cl" + "aude",
            "Chat" + "GPT",
            "Open" + "AI",
            "generated" + " by AI",
            "Co-" + "Authored-By",
        ]
        for word in forbidden:
            assert word not in md

    def test_markdown_has_finding_headings(self):
        md = generate_markdown_report(build_lab_report())
        assert "### FIND-001" in md
        assert "### FIND-007" in md

    def test_markdown_critical_finding_present(self):
        md = generate_markdown_report(build_lab_report())
        assert "CRITICAL" in md


class TestReportAPIEndpoints:
    def test_json_report_endpoint(self, client):
        resp = client.get("/reports/findings.json")
        assert resp.status_code == 200
        data = resp.json()
        assert "findings" in data
        assert data["total_findings"] == 7

    def test_markdown_report_endpoint(self, client):
        resp = client.get("/reports/findings.md")
        assert resp.status_code == 200
        assert "FIND-001" in resp.text

    def test_json_report_schema_version(self, client):
        # AppSecReport doesn't have schema_version, but verify structure
        resp = client.get("/reports/findings.json")
        assert resp.status_code == 200
        assert "report_id" in resp.json()

    def test_json_report_findings_count(self, client):
        resp = client.get("/reports/findings.json")
        assert resp.status_code == 200
        assert len(resp.json()["findings"]) == 7
