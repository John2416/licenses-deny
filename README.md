# licenses-deny

Simple CLI to inspect Python environment dependencies for license compliance, banned packages, and allowed sources.

## Requirements

- Python 3.11+
- Virtual environment activated before running checks (required by the tool)

## Installation

```bash
pip install licenses-deny
```

## Usage

```bash
# Initialize template configuration near project root
licenses-deny init

# List installed packages with detected license/source
licenses-deny list

# List and include raw license strings when they differ from the normalized value
licenses-deny list --show-raw-license

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