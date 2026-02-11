from collections.abc import Iterable
from importlib.metadata import Distribution, PackageMetadata
import json
from pathlib import Path
import sys
from typing import Any, cast

from .models import ClarifyRule, Config, PackageRecord, SourceInfo
from .utils import summarize_license


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
            return SourceInfo(label='pypi', kind='pypi')

        with direct_url_path.open('r', encoding='utf-8') as fp:
            data = cast(dict[str, Any], json.load(fp))

        url_field = data.get('url', '') or ''
        if 'vcs_info' in data:
            vcs = data['vcs_info'].get('vcs', 'vcs')
            ref = data['vcs_info'].get('commit_id') or data['vcs_info'].get('requested_revision', '')
            label = f'{vcs}:{url_field}@{ref}' if ref else f'{vcs}:{url_field}'
            return SourceInfo(label=label, kind='vcs')

        lowered = url_field.lower()
        if url_field.startswith('file://'):
            return SourceInfo(label=url_field, kind='dir')
        if lowered.startswith(('git+', 'ssh://', 'git@')):
            return SourceInfo(label=url_field, kind='vcs')
        if url_field:
            return SourceInfo(label=url_field, kind='url')

        return SourceInfo(label='pypi', kind='pypi')
    except Exception:
        return SourceInfo(label='unknown', kind='unknown')


def apply_clarify_rules(
    package: str,
    version: str,
    raw_license: str,
    clarify_rules: Iterable[ClarifyRule],
) -> tuple[str, bool]:
    for rule in clarify_rules:
        if rule.matches(package, version):
            return rule.license, True
    return raw_license, False


def resolve_allowed_set(pkg: PackageRecord, config: Config) -> set[str]:
    allowed = set(config.licenses.allow)
    for exc in config.licenses.exceptions:
        if exc.package != pkg.name:
            continue
        if exc.source and exc.source.lower() not in pkg.source.label.lower():
            continue
        allowed |= exc.allow
    return allowed


def collect_packages(config: Config) -> list[PackageRecord]:
    if not in_virtual_environment():
        print(
            'Error: This script must be run inside an activated virtual environment.', file=sys.stderr
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


def render_package_line(pkg: PackageRecord) -> str:
    license_part = summarize_license(pkg.effective_license)
    if pkg.clarified and pkg.effective_license != pkg.raw_license:
        license_part = (
            f'{summarize_license(pkg.effective_license)} (raw: {summarize_license(pkg.raw_license)})'
        )
    return f'{pkg.name}=={pkg.version} [{license_part}] source={pkg.source.label}'
