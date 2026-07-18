# Changelog

All notable changes to this project are documented here.

## [0.3.0]

### Added
- OS command injection SAST rule for `os.system` / `os.popen` and `subprocess` calls with `shell=True` (CWE-78).
- Disabled-TLS-verification SAST rule for HTTP client calls with `verify=False` (CWE-295).
- Secure code review write-up for OS command injection and disabled TLS verification (`docs/COMMAND_INJECTION_REVIEW.md`).
- SAST pattern coverage table in the README mapping every rule to its CWE and severity.

## [0.2.0]

### Added
- OWASP A02 Cryptographic Failures pair (unsalted MD5 vs bcrypt) and a weak-hash SAST rule (CWE-916).
- API-security coverage mapped to the OWASP API Security Top 10: BFLA and mass-assignment vulnerable/secure pairs, IDOR reframed as BOLA (`docs/API_SECURITY.md`).
- Insecure-deserialization SAST rule for pickle/marshal/yaml.load (CWE-502).
- Security CI pipeline: Bandit and Semgrep SARIF uploaded to the GitHub Security tab, plus pip-audit and gitleaks.
- Runnable proof-of-run demo (`scripts/demo.py`) with captured output in `docs/DEMO.md`.

## [0.1.0]

### Added
- Initial release: OWASP Top 10 vulnerable/fixed endpoint pairs (SQLi, IDOR, weak JWT, SSRF, XSS, insecure upload, debug endpoint), heuristic SAST and DAST checks, structured reporting, tests, and CI.
