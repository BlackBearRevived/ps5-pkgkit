#!/usr/bin/env python3
"""Regenerate ps5_pkgkit/format/keys.py from a reference ps5upload checkout.

The constants are vendored (see the generated module's docstring). This tool
keeps the provenance and the exact byte values reproducible:

    python3 tools/import_keys.py /path/to/ps5upload/engine/crates/ps5upload-fpkg/src/keys.rs
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re

WANTED = (
    "METADATA_MODULUS",
    "PASSCODE_MODULI",
    "MOUNT_IMAGE_MODULUS",
    "KEYSTONE_HMAC_1",
    "KEYSTONE_HMAC_2",
    "NAPS_META_18_DATA_KEY",
    "NAPS_META_18_TWEAK_KEY",
    "RIF_DEBUG_KEY",
    "DEBUG_RIF_MODULUS",
    "DEBUG_RIF_PRIVATE_EXPONENT",
)

HEADER = '''"""Fixed key material for the PS5 debug-package format.

Vendored at the project owner's direction from the reference FPKG
implementation (GPL-3.0-or-later, ps5upload revision
4174eee2319d45a488c37832a5b890de2f9c5358). These are the debug/fake-package
constants that reference uses; none is a retail production key. Keep every
copy in this module, so they can be replaced from one place.
"""
'''


def main() -> int:
    """Regenerate the vendored debug-format constants from the reference file.

    Returns:
        Zero after writing the output module.

    Raises:
        SystemExit: Command-line usage is invalid or a required constant is
            absent.
        OSError: The input cannot be opened or the output cannot be written.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("keys_rs", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "src/ps5_pkgkit/format/keys.py",
    )
    args = parser.parse_args()
    text = args.keys_rs.read_text(encoding="utf-8")

    lines = [HEADER]
    for name in WANTED:
        match = re.search(
            r"pub const " + name + r": \[u8; [0-9_]+\] = \[(.*?)\];", text, re.S
        )
        if match is None:
            raise SystemExit(f"missing {name} in {args.keys_rs}")
        values = re.findall(r"0x([0-9a-fA-F]{2})", match.group(1))
        lines.append(f"{name} = bytes.fromhex(")
        chunk = ""
        for value in values:
            chunk += value
            if len(chunk) >= 64:
                lines.append(f'    "{chunk}"')
                chunk = ""
        if chunk:
            lines.append(f'    "{chunk}"')
        lines.append(")")
        lines.append("")

    sector = re.search(
        r"pub const NAPS_META_18_TWEAK_SECTOR: u64 = 0x([0-9A-Fa-f_]+);", text
    )
    if sector is None:
        raise SystemExit(f"missing NAPS_META_18_TWEAK_SECTOR in {args.keys_rs}")
    lines.append(f'NAPS_META_18_TWEAK_SECTOR = 0x{sector.group(1).replace("_", "")}')
    lines.append("")
    args.output.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
