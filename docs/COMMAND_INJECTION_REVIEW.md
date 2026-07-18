# Secure Code Review — OS Command Injection & Disabled TLS Verification

This note walks through two SAST rules added to the lab scanner, in the format of a
short secure code review: the vulnerable pattern, why it is dangerous, the CWE, and
the fixed version.

---

## 1. OS Command Injection (CWE-78)

### Vulnerable

```python
import os

def ping_host(user_host: str):
    # user_host comes straight from an HTTP query parameter
    return os.system("ping -c 1 " + user_host)
```

A request such as `?host=127.0.0.1;cat /etc/passwd` is passed to the shell verbatim.
The `;` terminates the `ping` command and the shell then executes `cat /etc/passwd`.
The same problem appears with `os.popen(...)` and with `subprocess` calls that pass
`shell=True`:

```python
subprocess.run(f"ping -c 1 {user_host}", shell=True)   # equally injectable
```

**Why it matters:** the attacker runs arbitrary commands with the privileges of the
web process — reading files, opening a reverse shell, or pivoting into the network.

**Detected as:** `OS_COMMAND_INJECTION`, severity `critical`.

### Fixed

Never build a shell string from user input. Pass arguments as a list and keep
`shell=False` (the default), so the OS executes the binary directly with no shell
interpretation:

```python
import subprocess

def ping_host(user_host: str):
    # validate/whitelist first (e.g. that user_host is a hostname or IP)
    return subprocess.run(
        ["ping", "-c", "1", user_host],
        shell=False,
        capture_output=True,
        timeout=5,
    )
```

The argument vector means `127.0.0.1;cat /etc/passwd` is treated as a single
(invalid) host argument, not as two shell commands.

---

## 2. Disabled TLS Verification (CWE-295)

### Vulnerable

```python
import requests

resp = requests.get("https://api.internal.example/secret", verify=False)
```

`verify=False` disables certificate validation. The client will accept **any**
certificate, including a self-signed one presented by a man-in-the-middle. TLS still
encrypts the channel, but the identity of the peer is no longer proven — so an
attacker on the path can transparently intercept and modify the traffic.

`verify=False` is also commonly copied from a "make the SSL error go away" answer and
then shipped to production.

**Detected as:** `DISABLED_TLS_VERIFICATION`, severity `high`.

> Note: the scanner deliberately does **not** flag `{"verify_exp": False}` (a JWT
> option), which is a different finding handled by the `JWT_WEAK_OPTIONS` rule.

### Fixed

Leave verification on (the default) and fix the underlying trust problem instead —
install the proper CA, or pin the internal CA bundle:

```python
import requests

# Default: verify=True. For a private CA, point at its bundle rather than disabling.
resp = requests.get(
    "https://api.internal.example/secret",
    verify="/etc/ssl/certs/internal-ca.pem",
    timeout=5,
)
```

---

## Review checklist

- [ ] No `os.system` / `os.popen` on any value derived from user input.
- [ ] `subprocess` calls use an argument list and `shell=False`.
- [ ] Untrusted host/path input is validated or whitelisted before use.
- [ ] No `verify=False` on any outbound HTTPS call.
- [ ] Private CAs are trusted via a CA bundle, not by disabling verification.
