#!/usr/bin/env python3
"""Build a package from a folder and compare it with a reference package.

    python3 tools/compare_reference.py SOURCE_FOLDER REFERENCE.pkg OUTPUT.pkg

The reference's SI ZIP timestamp is reused, so a byte-identical build has the
same SHA-256.
"""

from __future__ import annotations

import hashlib
import io
from pathlib import Path
import sys
import time
import zipfile

from ps5_pkgkit import build_package


def main() -> int:
    """Build from command-line paths and compare with a reference package.

    Reuse the reference archive's member timestamp so identical output can be
    confirmed by its SHA-256 digest.

    Returns:
        Zero for matching digests or one when the built package differs.
    """
    source, reference, output = (Path(argument) for argument in sys.argv[1:4])
    data = reference.read_bytes()
    cnt_at = int.from_bytes(data[0x58:0x60], "little")
    si_at = cnt_at + int.from_bytes(data[cnt_at + 0x7C:cnt_at + 0x80], "big")
    archive = zipfile.ZipFile(io.BytesIO(data[si_at:]))
    year, month, day, hour, minute, second = archive.infolist()[0].date_time
    stamp = time.mktime((year, month, day, hour, minute, second, 0, 0, -1))
    result = build_package(source, output, timestamp=stamp)
    expected = hashlib.sha256(data).hexdigest()
    print(f"reference {expected}")
    print(f"built     {result.sha256}")
    print("identical" if result.sha256 == expected else "different")
    return 0 if result.sha256 == expected else 1


if __name__ == "__main__":
    raise SystemExit(main())
