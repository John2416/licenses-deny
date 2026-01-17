# licenses-deny

Simple CLI to inspect Python environment dependencies for license compliance, banned packages, and allowed sources.

## Requirements

- Python 3.11+
- Virtual environment activated before running checks (required by the tool)

## Installation

```bash
pip install .
```

## Usage

```bash
# Initialize template configuration near project root
licenses-deny init

# List installed packages with detected license/source
licenses-deny list

# Run checks (licenses + bans + sources)
licenses-deny check

# Run only license checks in strict mode
licenses-deny check licenses --strict
```

## Development

```bash
# Install in editable mode
pip install -e .

# Run CLI directly from source
python -m licenses_deny --help
```
