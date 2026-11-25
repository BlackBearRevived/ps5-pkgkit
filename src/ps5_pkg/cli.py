"""Command-line interface for ps5-pkg."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

from .verification import VerificationError, verify_package


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ps5-pkg", description="Verify existing PS5 application packages.")
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="check package structure and container checksums")
    verify.add_argument("package", type=Path)
    verify.add_argument("--sha256", help="compare the entire file with a trusted SHA-256")
    verify.add_argument("--json", action="store_true", help="print a machine-readable report")
    args = parser.parse_args(argv)

    try:
        report = verify_package(args.package, expected_sha256=args.sha256)
    except (OSError, VerificationError) as error:
        if args.json:
            print(json.dumps({"error": str(error)}), file=sys.stderr)
        else:
            print(f"ps5-pkg: {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(asdict(report)))
    else:
        print(f"Container verified for {report.title_id} {report.content_version}")
        print(f"Content ID: {report.content_id}")
        print(f"Container entries: {report.container_entries}")
        confirmation = " (matches trusted SHA-256)" if report.expected_sha256_verified else ""
        print(f"SHA-256: {report.sha256}{confirmation}")
    return 0
