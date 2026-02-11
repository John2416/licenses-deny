import sys

from .models import BanRule, Config, PackageRecord, SourcePolicy
from .packages import render_package_line, resolve_allowed_set
from .utils import is_license_compliant, summarize_license


def check_licenses(packages: list[PackageRecord], config: Config, strict: bool, quiet: bool) -> bool:
    violations: list[str] = []
    if not config.licenses.allow:
        print('Warning: [licenses.allow] is empty. All licenses will be rejected.', file=sys.stderr)
    for pkg in packages:
        allowed_set = resolve_allowed_set(pkg, config)
        compliant = is_license_compliant(pkg.effective_license, allowed_set, strict)
        if compliant:
            if not quiet:
                status = 'clarified' if pkg.clarified else 'metadata'
                print(
                    f'[ok:{status}] {pkg.name}=={pkg.version} ({summarize_license(pkg.effective_license)})'
                )
            continue
        detail = (
            f'{pkg.name}=={pkg.version} uses unapproved license: '
            f'{summarize_license(pkg.effective_license)} (raw: {summarize_license(pkg.raw_license)})'
            if pkg.effective_license != pkg.raw_license
            else f'{pkg.name}=={pkg.version} uses unapproved license: {summarize_license(pkg.effective_license)}'
        )
        violations.append(detail)
    if violations:
        print('\nLicense policy violation detected:', file=sys.stderr)
        print('-' * 60, file=sys.stderr)
        for line in violations:
            print(f'  {line}', file=sys.stderr)
        return False
    if not quiet:
        print('\nAll dependencies comply with license policy!')
    return True


def check_bans(packages: list[PackageRecord], ban_rules: list[BanRule], quiet: bool) -> bool:
    if not ban_rules:
        if not quiet:
            print('No bans configured; skipping.')
        return True
    banned_map = {rule.name: rule.reason for rule in ban_rules}
    hits = [(pkg, banned_map[pkg.name]) for pkg in packages if pkg.name in banned_map]
    if hits:
        print('\nBanned dependencies detected:', file=sys.stderr)
        print('-' * 60, file=sys.stderr)
        for pkg, reason in hits:
            suffix = f' reason: {reason}' if reason else ''
            print(f'  {pkg.name}=={pkg.version}{suffix}', file=sys.stderr)
        return False
    if not quiet:
        print('No banned dependencies found.')
    return True


def is_source_allowed(source, allowlist: list[str]) -> bool:
    if source.kind == 'pypi':
        return True
    if not allowlist:
        return False
    label_lower = source.label.lower()
    return any(allowed.lower() in label_lower for allowed in allowlist)


def check_sources(packages: list[PackageRecord], source_policy: SourcePolicy, quiet: bool) -> bool:
    violations: list[PackageRecord] = [
        pkg for pkg in packages if not is_source_allowed(pkg.source, source_policy.allowlist)
    ]
    if violations:
        print('\nNon-PyPI sources found (not in allowlist):', file=sys.stderr)
        print('-' * 60, file=sys.stderr)
        for pkg in violations:
            print(f'  {pkg.name}=={pkg.version} source={pkg.source.label}', file=sys.stderr)
        return False
    if not quiet:
        print('All dependencies originate from allowed sources.')
    return True


def list_packages(packages: list[PackageRecord]) -> None:
    for pkg in packages:
        print(render_package_line(pkg))
