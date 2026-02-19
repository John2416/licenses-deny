from collections.abc import Iterable
from importlib.metadata import Distribution, PackageMetadata
import json
from pathlib import Path
import re
import sys
from typing import Any, cast

from .models import ClarifyRule, Config, PackageRecord, SourceInfo, SourceKind
from .utils import normalize_license, summarize_license, tokenize_license_expression


def in_virtual_environment() -> bool:
    """Check if running inside a virtual environment."""
    return hasattr(sys, 'real_prefix') or (
        hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix
    )


def extract_license_from_metadata(dist: Distribution) -> str:
    try:
        metadata: PackageMetadata = dist.metadata
        expr = (metadata.get('License-Expression') or '').strip()
        if expr:
            return expr

        license_field = (metadata.get('License') or '').strip()
        if license_field and license_field not in ('UNKNOWN', 'Other/Proprietary'):
            return license_field
        for classifier in metadata.get_all('Classifier', []):
            if classifier.startswith('License ::'):
                lowered = classifier.lower()
                if 'python software foundation license' in lowered:
                    return 'PSF-2.0'
                if 'mit' in lowered:
                    return 'MIT'
                if 'apache' in lowered and '2.0' in lowered:
                    return 'Apache-2.0'
                if 'bsd' in lowered:
                    if '3-clause' in lowered or 'three clause' in lowered:
                        return 'BSD-3-Clause'
                    return 'BSD'
                if 'public domain' in lowered:
                    return 'Public Domain'
                if 'mozilla public license 2.0' in lowered:
                    return 'MPL-2.0'
        return 'Unknown'
    except Exception:
        return 'Unknown'


def resolve_source(dist: Distribution) -> SourceInfo:
    try:
        direct_url_path: Path | None = None
        files = getattr(dist, 'files', None) or []
        for entry in files:
            if entry.name == 'direct_url.json':
                candidate = Path(str(dist.locate_file(entry)))
                if candidate.is_file():
                    direct_url_path = candidate
                    break
        if direct_url_path is None:
            candidate = Path(str(dist.locate_file('direct_url.json')))
            if candidate.is_file():
                direct_url_path = candidate
        if direct_url_path is None:
            return SourceInfo(label='pypi', kind=SourceKind.PYPI)

        with direct_url_path.open('r', encoding='utf-8') as fp:
            data = cast(dict[str, Any], json.load(fp))

        url_field = data.get('url', '') or ''
        if 'vcs_info' in data:
            vcs = data['vcs_info'].get('vcs', 'vcs')
            ref = data['vcs_info'].get('commit_id') or data['vcs_info'].get('requested_revision', '')
            label = f'{vcs}:{url_field}@{ref}' if ref else f'{vcs}:{url_field}'
            return SourceInfo(label=label, kind=SourceKind.GIT)

        lowered = url_field.lower()
        if url_field.startswith('file://'):
            return SourceInfo(label=url_field, kind=SourceKind.DIR)
        if lowered.startswith(('git+', 'ssh://', 'git@')):
            return SourceInfo(label=url_field, kind=SourceKind.GIT)
        if url_field:
            return SourceInfo(label=url_field, kind=SourceKind.REGISTRY)

        return SourceInfo(label='pypi', kind=SourceKind.PYPI)
    except Exception:
        return SourceInfo(label='unknown', kind=SourceKind.UNKNOWN)


def apply_clarify_rules(
    package: str,
    version: str,
    raw_license: str,
    clarify_rules: Iterable[ClarifyRule],
) -> tuple[str, bool]:
    for rule in clarify_rules:
        if rule.matches(package, version):
            return rule.expression, True
    return raw_license, False


def resolve_allowed_set(pkg: PackageRecord, config: Config) -> set[str]:
    allowed = set(config.licenses.allow)
    for exc in config.licenses.exceptions:
        if exc.package != pkg.name:
            continue
        allowed |= exc.allow
    return allowed


def collect_packages(config: Config) -> list[PackageRecord]:
    if not in_virtual_environment():
        print(
            'Error: This script must be run inside an activated virtual environment.',
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        import importlib.metadata as ilm
    except Exception as exc:
        print(f'Error: unable to access importlib.metadata: {exc}', file=sys.stderr)
        sys.exit(1)

    records: list[PackageRecord] = []
    for dist in ilm.distributions():
        name = dist.metadata.get('Name')
        if not name:
            continue
        package = name.lower()
        version = dist.version
        raw_license = extract_license_from_metadata(dist)
        effective_license, clarified = apply_clarify_rules(
            package, version, raw_license, config.licenses.clarify_rules
        )
        source = resolve_source(dist)
        records.append(
            PackageRecord(
                name=package,
                version=version,
                raw_license=raw_license,
                effective_license=effective_license,
                clarified=clarified,
                source=source,
            )
        )
    records.sort(key=lambda r: r.name)
    return records


def _normalize_license_for_display(value: str) -> str:
    if not value:
        return value
    tokens = tokenize_license_expression(value, strict=False)
    if not tokens:
        return value.strip()

    has_expression = any(tok in ('AND', 'OR') for tok in tokens) or any(
        tok in ('(', ')') for tok in tokens
    )
    if not has_expression:
        return normalize_license(value)

    normalized_tokens: list[str] = []
    for tok in tokens:
        if tok in ('AND', 'OR', '(', ')'):
            normalized_tokens.append(tok)
        else:
            normalized_tokens.append(normalize_license(tok))

    # Keep expression readable: normalize spacing and parentheses.
    text = ' '.join(normalized_tokens)
    text = re.sub(r'\s*\(\s*', '(', text)
    text = re.sub(r'\s*\)\s*', ')', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def format_license_display(pkg: PackageRecord, show_raw_license: bool = False) -> str:
    primary = summarize_license(_normalize_license_for_display(pkg.effective_license))
    if show_raw_license:
        raw = summarize_license(pkg.raw_license)
        if raw and raw != primary:
            return f'{primary} (raw: {raw})'
    return primary


def render_package_line(pkg: PackageRecord, show_raw_license: bool = False) -> str:
    license_part = format_license_display(pkg, show_raw_license=show_raw_license)
    return f'{pkg.name}=={pkg.version} [{license_part}] source={pkg.source.label}'
