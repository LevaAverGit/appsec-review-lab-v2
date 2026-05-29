# Setup

> **Python 3.11+ is required.** The codebase uses `str | None` union syntax introduced in Python 3.10 and is tested on 3.11.
>
> If you use pyenv:
> ```bash
> pyenv install 3.11
> pyenv local 3.11
> python --version  # should show 3.11.x
> ```

## Install

```bash
git clone https://github.com/LevaAverGit/appsec-review-lab
cd appsec-review-lab

python3.11 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt

# Or with make:
make install
```

## Run tests

```bash
make test
# or
.venv/bin/pytest -v
```

Expected output: `159 passed, 1 warning`

## Start the API

```bash
make run-api
# FastAPI at http://127.0.0.1:8001
# Interactive docs at http://127.0.0.1:8001/docs
```

## Environment variables

All settings have defaults. Override with `APPSEC_` prefix:

| Variable | Default | Description |
|---|---|---|
| `APPSEC_DB_PATH` | `lab.db` | SQLite database path |
| `APPSEC_JWT_SECRET` | fake lab value | JWT signing secret |
| `APPSEC_JWT_EXPIRE_MINUTES` | `30` | JWT token lifetime |
| `APPSEC_UPLOAD_DIR` | `/tmp/appsec_lab_uploads` | File upload directory |
| `APPSEC_MAX_UPLOAD_BYTES` | `1048576` | Max upload size (1 MB) |

The default JWT secret is a clearly labelled fake value and must be replaced in any deployment.
