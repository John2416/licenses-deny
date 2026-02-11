from pathlib import Path
import re
import tomllib

from packaging.specifiers import InvalidSpecifier, SpecifierSet

from .constants import CONFIG_FILENAME, ROOT_MARKERS, TEMPLATE_CONFIG
from .models import BanRule, ClarifyRule, Config, LicenseException, LicensePolicy, SourcePolicy


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
    exceptions: list[LicenseException] = []
    for exc in licenses_cfg.get('exceptions', []):
        pkg = exc.get('package', '')
        allow_list = exc.get('allow', [])
        source_label = exc.get('source')
        if pkg and allow_list:
            exceptions.append(
                LicenseException(package=pkg.lower(), allow=set(allow_list), source=source_label)
            )

    clarify_rules: list[ClarifyRule] = []
    for entry in licenses_cfg.get('clarify', []):
        pkg = entry.get('package', '')
        license_expr = entry.get('license', '')
        version_spec = entry.get('version', '')
        if not pkg or not license_expr:
            continue
        parsed_spec = parse_version_spec(version_spec) if version_spec else None
        rule = ClarifyRule(
            package=pkg.lower(),
            license=license_expr,
            version_spec=parsed_spec,
        )
        clarify_rules.append(rule)

    bans_cfg = raw_config.get('bans', {}) or {}
    ban_rules: list[BanRule] = []
    for entry in bans_cfg.get('packages', []):
        name = entry.get('name', '')
        reason = entry.get('reason')
        if name:
            ban_rules.append(BanRule(name=name.lower(), reason=reason))

    sources_cfg = raw_config.get('sources', {}) or {}
    allowlist = sources_cfg.get('allow', []) or []

    return Config(
        licenses=LicensePolicy(allow=allow, exceptions=exceptions, clarify_rules=clarify_rules),
        bans=ban_rules,
        sources=SourcePolicy(allowlist=allowlist),
    )
