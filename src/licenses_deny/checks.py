import sys
from urllib.parse import urlsplit

from .models import (
    BanPolicy,
    BanRule,
    Config,
    Decision,
    PackageRecord,
    SourceInfo,
    SourceKind,
    SourcePolicy,
)
from .packages import render_package_line, resolve_allowed_set
from .utils import (
    is_copyleft,
    is_license_compliant,
    normalize_license,
    normalized_license_parts,
    summarize_license,
)


def _decision_allows(decision: Decision) -> tuple[bool, bool]:
    """Return (allowed, warn_only) for a policy decision."""
    return (decision != Decision.DENY, decision == Decision.WARN)


def check_licenses(packages: list[PackageRecord], config: Config, strict: bool, quiet: bool) -> bool:
    violations: list[str] = []
    warnings: list[str] = []

    if not config.licenses.allow:
        print(
            'Warning: [licenses.allow] is empty; all licenses will be rejected unless explicitly excepted.',
            file=sys.stderr,
        )

    for pkg in packages:
        # Skip license evaluation for private packages when configured to ignore
        if config.licenses.private.ignore:
            label_lower = pkg.source.label.lower()
            if any(reg.lower() in label_lower for reg in config.licenses.private.registries):
                if not quiet:
                    print(
                        f'[ok:private] {pkg.name}=={pkg.version} (license check skipped)',
                        file=sys.stderr,
                    )
                continue

        allowed_set = resolve_allowed_set(pkg, config)

        if pkg.effective_license == 'Unknown' or not pkg.effective_license:
            allowed, warn = _decision_allows(config.licenses.unlicensed)
            if warn:
                warnings.append(f'{pkg.name} has no license information (policy=warn)')
            if not allowed:
                violations.append(f'{pkg.name}=={pkg.version} is unlicensed/unknown (policy=deny)')
            continue

        normalized_parts = normalized_license_parts(pkg.effective_license) or {
            normalize_license(pkg.effective_license)
        }

        if any(part in config.licenses.deny for part in normalized_parts):
            violations.append(
                f'{pkg.name}=={pkg.version} uses denied license: {summarize_license(pkg.effective_license)}'
            )
            continue

        compliant = is_license_compliant(pkg.effective_license, allowed_set, strict)
        if not compliant:
            violations.append(
                f'{pkg.name}=={pkg.version} uses unapproved license: {summarize_license(pkg.effective_license)}'
            )
            continue

        if any(is_copyleft(part) for part in normalized_parts):
            allowed, warn = _decision_allows(config.licenses.copyleft)
            if warn:
                warnings.append(f'{pkg.name}=={pkg.version} is copyleft-licensed (policy=warn)')
            if not allowed:
                violations.append(
                    f'{pkg.name}=={pkg.version} is copyleft-licensed: {summarize_license(pkg.effective_license)}'
                )
                continue

        if not quiet:
            status = 'clarified' if pkg.clarified else 'metadata'
            print(
                f'[ok:{status}] {pkg.name}=={pkg.version} ({summarize_license(pkg.effective_license)})'
            )

    for msg in warnings:
        print(f'Warning: {msg}', file=sys.stderr)

    if violations:
        print('\nLicense policy violation detected:', file=sys.stderr)
        print('-' * 60, file=sys.stderr)
        for line in violations:
            print(f'  {line}', file=sys.stderr)
        print()
        return False
    if not quiet:
        print('All dependencies comply with license policy!')
    return True


def check_bans(packages: list[PackageRecord], bans: BanPolicy, quiet: bool) -> bool:
    if not bans.deny and not bans.skip:
        if not quiet:
            print('No bans configured; skipping.')
        return True

    deny_map = {rule.name: rule.reason for rule in bans.deny}
    skip_map = {rule.name: rule.reason for rule in bans.skip}

    hits: list[tuple[PackageRecord, str | None]] = []
    skipped: list[tuple[PackageRecord, str | None]] = []

    for pkg in packages:
        if pkg.name in skip_map:
            skipped.append((pkg, skip_map[pkg.name]))
            continue
        if pkg.name in deny_map:
            hits.append((pkg, deny_map[pkg.name]))

    if skipped and not quiet:
        print('Bans skipped by configuration:', file=sys.stderr)
        for pkg, reason in skipped:
            suffix = f' reason: {reason}' if reason else ''
            print(f'  {pkg.name}=={pkg.version}{suffix}', file=sys.stderr)

    if hits:
        print('\nBanned dependencies detected:', file=sys.stderr)
        print('-' * 60, file=sys.stderr)
        for pkg, reason in hits:
            suffix = f' reason: {reason}' if reason else ''
            print(f'  {pkg.name}=={pkg.version}{suffix}', file=sys.stderr)
        print()
        return False
    if not quiet:
        print('No banned dependencies found.')
    return True


def _matches_allowed_org(label: str, allow_org: dict[str, list[str]]) -> bool:
    cleaned = label
    for prefix in ('git+', 'ssh+', 'git:'):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :]
    parsed = urlsplit(cleaned)
    host = (parsed.hostname or '').lower()
    path_parts = [p for p in parsed.path.split('/') if p]
    org = path_parts[0].lower() if path_parts else ''

    for host_key, orgs in allow_org.items():
        if host_key.lower() in host and org in (o.lower() for o in orgs):
            return True
    return False


def is_source_allowed(source: SourceInfo, source_policy: SourcePolicy) -> tuple[bool, bool]:
    """Return (allowed, warn_only)."""
    label_lower = source.label.lower()

    if source.kind == SourceKind.PYPI:
        return True, False

    if source.kind == SourceKind.DIR:
        return True, False

    if source.kind == SourceKind.GIT:
        if any(allowed.lower() in label_lower for allowed in source_policy.allow_git):
            return True, False
        if _matches_allowed_org(source.label, source_policy.allow_org):
            return True, False
        return _decision_allows(source_policy.unknown_git)

    if source.kind in {SourceKind.REGISTRY, SourceKind.URL, SourceKind.DIR, SourceKind.UNKNOWN}:
        if any(allowed.lower() in label_lower for allowed in source_policy.allow_registry):
            return True, False
        return _decision_allows(source_policy.unknown_registry)

    return False, False


def check_sources(packages: list[PackageRecord], source_policy: SourcePolicy, quiet: bool) -> bool:
    violations: list[str] = []
    warnings: list[str] = []

    for pkg in packages:
        allowed, warn = is_source_allowed(pkg.source, source_policy)
        if warn:
            warnings.append(f'{pkg.name}=={pkg.version} source={pkg.source.label} (policy=warn)')
        if not allowed:
            violations.append(f'{pkg.name}=={pkg.version} source={pkg.source.label}')

    for msg in warnings:
        print(f'Warning: {msg}', file=sys.stderr)

    if violations:
        print('\nNon-allowed sources detected:', file=sys.stderr)
        print('-' * 60, file=sys.stderr)
        for line in violations:
            print(f'  {line}', file=sys.stderr)
        print()
        return False
    if not quiet:
        print('All dependencies originate from allowed sources.')
    return True


def list_packages(packages: list[PackageRecord]) -> None:
    for pkg in packages:
        print(render_package_line(pkg))
