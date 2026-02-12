from pathlib import Path
import re
import tomllib

from packaging.specifiers import InvalidSpecifier, SpecifierSet

from .constants import CONFIG_FILENAME, ROOT_MARKERS
from .models import (
    BanPolicy,
    BanRule,
    ClarifyRule,
    Config,
    Decision,
    LicenseException,
    LicensePolicy,
    PrivatePolicy,
    SourcePolicy,
)


def find_project_root(start: Path | None = None) -> Path:
    current = start or Path.cwd()
    for path in [current, *current.parents]:
        if any((path / marker).exists() for marker in ROOT_MARKERS):
            return path
    return current


def locate_config_path() -> Path:
    root = find_project_root()
    candidate = root / CONFIG_FILENAME
    if candidate.is_file():
        return candidate
    raise FileNotFoundError(
        f"Configuration file '{CONFIG_FILENAME}' not found near {root}. "
        'Run `licenses-deny init` to create a template.'
    )


def parse_version_spec(spec_str: str) -> SpecifierSet | None:
    spec = spec_str.strip()
    if not spec:
        return None

    normalized = spec
    if normalized.startswith('=') and not normalized.startswith('=='):
        normalized = '==' + normalized.lstrip('=')
    elif not re.match(r'^[<>=!~]', normalized):
        normalized = f'=={normalized}'

    try:
        return SpecifierSet(normalized)
    except InvalidSpecifier:
        return None


def load_config(config_path: Path) -> Config:
    with config_path.open('rb') as fp:
        raw_config = tomllib.load(fp)

    licenses_cfg = raw_config.get('licenses', {}) or {}
    allow = set(licenses_cfg.get('allow', []))
    deny = set(licenses_cfg.get('deny', []))

    exceptions: list[LicenseException] = []
    for exc in licenses_cfg.get('exceptions', []):
        pkg = exc.get('package', '')
        allow_list = exc.get('allow', [])
        reason = exc.get('reason')
        if pkg and allow_list:
            exceptions.append(
                LicenseException(package=pkg.lower(), allow=set(allow_list), reason=reason)
            )

    clarify_rules: list[ClarifyRule] = []
    for entry in licenses_cfg.get('clarify', []):
        pkg = entry.get('package', '')
        expression = entry.get('expression', '')
        version_spec = entry.get('version', '')
        link = entry.get('link')
        if not pkg or not expression:
            continue
        parsed_spec = parse_version_spec(version_spec) if version_spec else None
        rule = ClarifyRule(
            package=pkg.lower(),
            expression=expression,
            version_spec=parsed_spec,
            link=link,
        )
        clarify_rules.append(rule)

    private_cfg = licenses_cfg.get('private', {}) or {}
    private_policy = PrivatePolicy(
        ignore=bool(private_cfg.get('ignore', False)),
        registries=list(private_cfg.get('registries', []) or []),
    )

    license_policy = LicensePolicy(
        allow=allow,
        deny=deny,
        unlicensed=Decision.from_str(licenses_cfg.get('unlicensed'), Decision.DENY),
        exceptions=exceptions,
        clarify_rules=clarify_rules,
        private=private_policy,
    )

    bans_cfg = raw_config.get('bans', {}) or {}
    deny_bans: list[BanRule] = []
    for entry in bans_cfg.get('deny', []):
        name = entry.get('name', '')
        reason = entry.get('reason')
        if name:
            deny_bans.append(BanRule(name=name.lower(), reason=reason))

    skip_bans: list[BanRule] = []
    for entry in bans_cfg.get('skip', []):
        name = entry.get('name', '')
        reason = entry.get('reason')
        if name:
            skip_bans.append(BanRule(name=name.lower(), reason=reason))

    bans_policy = BanPolicy(deny=deny_bans, skip=skip_bans)

    sources_cfg = raw_config.get('sources', {}) or {}
    source_policy = SourcePolicy(
        unknown_registry=Decision.from_str(sources_cfg.get('unknown-registry'), Decision.DENY),
        unknown_git=Decision.from_str(sources_cfg.get('unknown-git'), Decision.DENY),
        allow_registry=list(sources_cfg.get('allow-registry', []) or []),
        allow_git=list(sources_cfg.get('allow-git', []) or []),
        allow_org={k: list(v) for k, v in (sources_cfg.get('allow-org', {}) or {}).items()},
    )

    return Config(licenses=license_policy, bans=bans_policy, sources=source_policy)
