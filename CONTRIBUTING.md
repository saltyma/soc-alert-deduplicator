# Contributing

## Development setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
pip install -e .
```

## Quality gate

```powershell
ruff check .
ruff format --check .
mypy src
coverage run -m pytest
coverage report
```

## Design rules

- Keep alert values as data; never execute input content.
- Preserve deterministic ordering and source alert IDs.
- Keep presentation code separate from grouping logic.
- Add tests for successful behavior and failure paths.
- Update the threat model when a new input, output, or trust boundary is introduced.
- Use only synthetic or explicitly sanitized data in the public repository.
