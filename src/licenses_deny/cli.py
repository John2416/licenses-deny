import argparse
from pathlib import Path
import sys

from .checks import check_bans, check_licenses, check_sources, list_packages
from .config import (
    CONFIG_FILENAME,
    TEMPLATE_CONFIG,
    find_project_root,
    load_config,
    locate_config_path,
)
from .packages import collect_packages


def handle_init(force: bool) -> None:
    target_dir = find_project_root()
    target_path = target_dir / CONFIG_FILENAME
    if target_path.exists() and not force:
        print(
            f"Config already exists at {target_path}. Use --force to overwrite.",
            file=sys.stderr,
        )
        sys.exit(1)
    if target_path.exists() and force:
        print(f"Warning: Overwriting existing config at {target_path}", file=sys.stderr)
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path.write_text(TEMPLATE_CONFIG, encoding="utf-8")
    print(f"Template config written to {target_path}")


def handle_list(config_path: Path) -> None:
    config = load_config(config_path)
    packages = collect_packages(config)
    list_packages(packages)


def handle_check(scope: str, config_path: Path, strict: bool, quiet: bool) -> None:
    config = load_config(config_path)
    packages = collect_packages(config)
    success = True
    if scope in ("all", "sources"):
        success &= check_sources(packages, config.sources, quiet)
    if scope in ("all", "bans"):
        success &= check_bans(packages, config.bans, quiet)
    if scope in ("all", "licenses"):
        success &= check_licenses(packages, config, strict, quiet)
    if not success:
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check third-party dependency licenses and sources against allowlists."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser(
        "init", help="Create a template licenses-deny.toml near the project root."
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing config file if present.",
    )

    subparsers.add_parser("list", help="List dependencies with licenses and sources.")

    check_parser = subparsers.add_parser(
        "check",
        help="Run compliance checks (licenses, bans, sources).",
    )
    check_parser.add_argument(
        "scope",
        nargs="?",
        choices=["all", "licenses", "bans", "sources"],
        default="all",
        help="Which check to run (default: all).",
    )
    check_parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat compound license expressions (AND/OR) as requiring all licenses to be allowed.",
    )
    check_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress success logs on stdout.",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "init":
        handle_init(force=args.force)
        return

    try:
        config_path = locate_config_path()
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)

    if args.command == "list":
        handle_list(config_path)
        return

    if args.command == "check":
        handle_check(
            scope=args.scope,
            config_path=config_path,
            strict=args.strict,
            quiet=args.quiet,
        )
        return

    parser.error("Unknown command")


if __name__ == "__main__":
    main()
