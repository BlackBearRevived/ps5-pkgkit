"""Command-line interface for ps5-pkg."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

from . import __version__
from .build import BuildError, build_package
from .source import SourceError, inspect_source
from .verification import VerificationError, verify_package


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ps5-pkg",
        description="Build PS5 packages from staged title folders, inspect folders and "
                    "verify existing packages.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="build a package from a staged title folder")
    build.add_argument("source", type=Path)
    build.add_argument("-o", "--output", type=Path, required=True)
    build.add_argument("--content-id", help="override the content id from param.json")
    build.add_argument("--firmware", help="required system software version, e.g. 5.10")
    build.add_argument("--language", help="narrow the PlayGo languages to this one")
    build.add_argument("--stored", action="store_true",
                       help="store the inner image instead of Kraken-compressing it")
    build.add_argument("--level", choices=("fast", "balanced", "smallest"),
                       default="balanced", help="Kraken compression level")
    build.add_argument("--json", action="store_true", help="print a machine-readable report")
    inspect = commands.add_parser("inspect-source", help="validate and hash a staged title folder")
    inspect.add_argument("source", type=Path)
    inspect.add_argument("--json", action="store_true", help="print a machine-readable report")
    verify = commands.add_parser("verify", help="check package structure and container checksums")
    verify.add_argument("package", type=Path)
    verify.add_argument("--sha256", help="compare the entire file with a trusted SHA-256")
    verify.add_argument("--json", action="store_true", help="print a machine-readable report")
    args = parser.parse_args(argv)

    try:
        if args.command == "build":
            result = build_package(
                args.source, args.output, content_id=args.content_id,
                firmware=args.firmware, language=args.language,
                kraken=not args.stored, level=args.level)
            if args.json:
                print(json.dumps(asdict(result), default=str))
            else:
                for warning in result.warnings:
                    print(f"ps5-pkg: warning: {warning}", file=sys.stderr)
                print(f"Built {result.output} for {result.title_id} "
                      f"{result.content_version} ({result.file_count} files)")
                print(f"Content ID: {result.content_id}")
                print(f"Size: {result.size} bytes")
                print(f"SHA-256: {result.sha256}")
            return 0
        if args.command == "inspect-source":
            report = inspect_source(args.source)
        else:
            report = verify_package(args.package, expected_sha256=args.sha256)
    except (OSError, SourceError, VerificationError, BuildError, ValueError) as error:
        if getattr(args, "json", False):
            print(json.dumps({"error": str(error)}), file=sys.stderr)
        else:
            print(f"ps5-pkg: {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(asdict(report)))
    elif args.command == "inspect-source":
        print(f"Source verified for {report.title_id} {report.content_version}")
        print(f"Content ID: {report.content_id}")
        print(f"Files: {len(report.files)} ({report.total_size} bytes)")
        print(f"Manifest SHA-256: {report.manifest_sha256}")
    else:
        print(f"Container verified for {report.title_id} {report.content_version}")
        print(f"Content ID: {report.content_id}")
        print(f"Container entries: {report.container_entries}")
        confirmation = " (matches trusted SHA-256)" if report.expected_sha256_verified else ""
        print(f"SHA-256: {report.sha256}{confirmation}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
