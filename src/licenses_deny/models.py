from dataclasses import dataclass, field

from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion


@dataclass
class ClarifyRule:
    package: str
    license: str
    version_spec: SpecifierSet | None

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
    source: str | None = None


@dataclass
class LicensePolicy:
    allow: set[str] = field(default_factory=set)
    exceptions: list[LicenseException] = field(default_factory=list)
    clarify_rules: list[ClarifyRule] = field(default_factory=list)


@dataclass
class BanRule:
    name: str
    reason: str | None = None


@dataclass
class SourcePolicy:
    allowlist: list[str] = field(default_factory=list)


@dataclass
class Config:
    licenses: LicensePolicy
    bans: list[BanRule]
    sources: SourcePolicy


@dataclass
class SourceInfo:
    label: str
    kind: str


@dataclass
class PackageRecord:
    name: str
    version: str
    raw_license: str
    effective_license: str
    clarified: bool
    source: SourceInfo
