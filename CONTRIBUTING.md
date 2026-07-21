# Contributing to MispFleet

Thanks for your interest in contributing!

## Development setup

```bash
python3.14 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

Python 3.14 is the only supported runtime.

## Quality gates

Every change must pass, with zero errors and zero warnings:

```bash
black --check .
ruff check .
mypy .
pytest          # 100% coverage enforced
bandit -r .
pip-audit
```

Suppression comments (`# noqa`, `# type: ignore`, `# nosec`) and tool exclusions
are not accepted: fix the code instead.

## Testing rules

- No mocks: tests exercise real code (a real local HTTP server stands in for MISP).
- Regression tests are required for bug fixes.
- Coverage must remain at 100%.

## Pull requests

- Keep changes focused and small.
- Update CHANGELOG.md under `Unreleased`.
- Public APIs are regression contracts: changing them requires updating all call
  sites, tests and documentation.
