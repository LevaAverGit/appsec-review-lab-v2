# Skills Mapping

Demonstrates junior/junior+ readiness for AppSec engineering, secure backend development, and SOC/security tooling tasks.

| Competency | Where demonstrated | Evidence |
|---|---|---|
| Python backend | FastAPI app, 3 service modules, Pydantic v2 | `app/main.py`, `app/services/` |
| Secure coding | 7 vulnerability-secure pairs with explicit mitigations | `app/api/routes_secure.py` |
| Vulnerability knowledge | SQL injection, IDOR, weak JWT, SSRF, XSS, file upload, misconfiguration | `app/api/routes_vulnerable.py`, `docs/VULNERABILITIES.md` |
| OWASP Top 10 | All 7 findings mapped to OWASP 2021 categories | `docs/OWASP_MAPPING.md`, `app/models/schemas.py` |
| CWE awareness | CWE-89, 639, 287, 347, 918, 79, 434, 22, 200 documented per finding | `app/services/report_service.py` |
| Static analysis (SAST) | Regex-based pattern scanner for dangerous coding patterns in Python source | `app/services/sast_checks.py` |
| Dynamic analysis (DAST) | In-process payload checks against running endpoints | `app/services/dast_checks.py` |
| JWT/auth engineering | Vulnerable vs secure JWT implementation side-by-side | `app/api/routes_secure.py`, `test_jwt.py` |
| SSRF prevention | URL validation with RFC1918/loopback/link-local guard | `routes_secure.py::_is_safe_url` |
| File upload security | Extension whitelist, UUID naming, size limit | `routes_secure.py::secure_upload` |
| Testing discipline | 151 tests, TestClient, tmp_path DB isolation, 0 failures | `tests/`, `docs/TESTING_APPROACH.md` |
| Reporting | Structured Markdown + JSON AppSec reports with findings model | `app/services/report_service.py` |
| API design | 9 + 9 paired endpoints, Pydantic v2 models | `app/api/` |
| CI/CD | GitHub Actions: Python 3.11, pytest mandatory, ruff non-blocking | `.github/workflows/ci.yml` |
| Documentation | 10 docs covering architecture, vulnerabilities, OWASP, limitations | `docs/` |

## Notes

This project intentionally avoids overclaiming:

- All exploit-style tests run only against the local in-process lab application.
- No real external hosts are contacted at any point.
- SAST/DAST checks are heuristic demonstrations, not production-grade scanners.
- Stated as a controlled lab, not a security product.
