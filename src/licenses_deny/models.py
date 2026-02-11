from dataclasses import dataclass, field
from enum import StrEnum

from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion


class Decision(StrEnum):
    ALLOW = 'allow'
    DENY = 'deny'
    WARN = 'warn'

    @classmethod
    def from_str(cls, value: str | None, default: 'Decision') -> 'Decision':
        if not value:
            return default
        lowered = value.strip().lower()
        for option in cls:
            if option.value == lowered:
                return option
        return default


class SourceKind(StrEnum):
    PYPI = 'pypi'
    REGISTRY = 'registry'
    GIT = 'git'
    DIR = 'dir'
    URL = 'url'
    UNKNOWN = 'unknown'


@dataclass
class ClarifyRule:
    package: str
    expression: str
    version_spec: SpecifierSet | None
    link: str | None = None

    def matches(self, package: str, version: str) -> bool:
        if self.package != package:
            return False
        if self.version_spec is None:
            return True
        try:
            return version in self.version_spec
        except InvalidVersion:
            return False


@dataclass
class LicenseException:
    package: str
    allow: set[str]
    reason: str | None = None


@dataclass
class PrivatePolicy:
    ignore: bool = False
    registries: list[str] = field(default_factory=list)


@dataclass
class LicensePolicy:
    allow: set[str] = field(default_factory=set)
    deny: set[str] = field(default_factory=set)
    unlicensed: Decision = Decision.DENY
    copyleft: Decision = Decision.DENY
    exceptions: list[LicenseException] = field(default_factory=list)
    clarify_rules: list[ClarifyRule] = field(default_factory=list)
    private: PrivatePolicy = field(default_factory=PrivatePolicy)


@dataclass
class BanRule:
    name: str
    reason: str | None = None


@dataclass
class BanPolicy:
    deny: list[BanRule] = field(default_factory=list)
    skip: list[BanRule] = field(default_factory=list)


@dataclass
class SourcePolicy:
    unknown_registry: Decision = Decision.DENY
    unknown_git: Decision = Decision.DENY
    allow_registry: list[str] = field(default_factory=list)
    allow_git: list[str] = field(default_factory=list)
    allow_org: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class Config:
    licenses: LicensePolicy
    bans: BanPolicy
    sources: SourcePolicy


@dataclass
class SourceInfo:
    label: str
    kind: SourceKind


@dataclass
class PackageRecord:
    name: str
    version: str
    raw_license: str
    effective_license: str
    clarified: bool
    source: SourceInfo
