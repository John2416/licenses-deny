from functools import lru_cache
from importlib import resources
import tomllib
from typing import Any

from .constants import MAPPING_FILENAME, MAPPING_PACKAGE


@lru_cache(maxsize=1)
def load_raw_mappings() -> dict[str, Any]:
    """Load the raw mapping TOML file as a dictionary."""
    try:
        mapping_path = resources.files(MAPPING_PACKAGE).joinpath(MAPPING_FILENAME)
        with mapping_path.open('rb') as fp:
            loaded = tomllib.load(fp)
        return loaded if isinstance(loaded, dict) else {}
    except (FileNotFoundError, tomllib.TOMLDecodeError, OSError):
        return {}


@lru_cache(maxsize=1)
def load_license_mapping() -> dict[str, str]:
    """Return a normalized license mapping with lowercase keys and string values."""
    raw = load_raw_mappings()
    license_map = raw.get('licenses') or {}
    if not isinstance(license_map, dict):
        return {}
    return {
        str(key).strip().lower(): str(value).strip()
        for key, value in license_map.items()
        if key is not None and value is not None
    }


@lru_cache(maxsize=1)
def multi_word_license_keys() -> list[str]:
    """Return multi-word license keys sorted by descending length (longest first)."""
    mapping = load_license_mapping()
    multi_word = [key for key in mapping if ' ' in key]
    return sorted(multi_word, key=len, reverse=True)
