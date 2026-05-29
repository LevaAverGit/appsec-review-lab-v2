.PHONY: install test lint clean run-api

install:
	python3.11 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt

test:
	.venv/bin/pytest -v --tb=short

lint:
	.venv/bin/ruff check app tests

clean:
	rm -rf .venv __pycache__ .pytest_cache dist

run-api:
	.venv/bin/uvicorn app.main:app --reload --port 8001
