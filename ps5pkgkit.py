#!/usr/bin/env python3
# PS5 PKG Kit - Command-line entry point for a checkout.
# Copyright (C) 2026 BlackBearReloaded
# SPDX-License-Identifier: GPL-3.0-or-later

"""Build, inspect and verify PS5 packages from a checkout.

Example: ./ps5_pkgkit.py build dist/PPSA99771 -o HelloWorld.pkg
Run with --help for all options.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from ps5_pkgkit.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
