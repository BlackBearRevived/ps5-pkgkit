# PS5 PKG Kit

Build, inspect and verify PlayStation 5 homebrew packages from staged title folders, in pure Python.

[![Build](https://github.com/BlackBearRevived/ps5-pkgkit/actions/workflows/ci.yml/badge.svg)](https://github.com/BlackBearRevived/ps5-pkgkit/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/BlackBearRevived/ps5-pkgkit)](https://github.com/BlackBearRevived/ps5-pkgkit/releases/latest)
[![License: GPL v3+](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)

The first tested inputs are the Hello World folder and reference package from the native boilerplate. The build runs on Windows, Linux and macOS with Python 3.11 or newer and needs nothing beyond the standard library.

## Install or run

Sign in to the GitHub CLI with an account that can access the repository, then
download the wheel and checksums from the release.

```bash
gh release download v0.1.0 -R BlackBearRevived/ps5-pkgkit -p '*.whl' -p SHA256SUMS.txt
sha256sum -c --ignore-missing SHA256SUMS.txt
```

### Run once with uvx

```bash
uvx --from ./ps5_pkgkit-0.1.0-py3-none-any.whl ps5-pkgkit --help
```

### Install with uv

```bash
uv tool install ./ps5_pkgkit-0.1.0-py3-none-any.whl
ps5-pkgkit --version
```

### Install with pip

Create a virtual environment with `python -m venv .venv`, activate it, then run:

```bash
python -m pip install ./ps5_pkgkit-0.1.0-py3-none-any.whl
ps5-pkgkit --version
```

You can also install from a local checkout with `python -m pip install .`.

### Download and run the zipapp

```bash
gh release download v0.1.0 -R BlackBearRevived/ps5-pkgkit -p ps5-pkgkit.pyz
python ps5-pkgkit.pyz --help
```

From a clone of this repository, `./ps5pkgkit.py` does the same, as does
`python -m ps5_pkgkit` once installed.

## Usage

```sh
ps5-pkgkit build dist/PPSA99771 -o HelloWorld.pkg
ps5-pkgkit inspect-source dist/PPSA99771
ps5-pkgkit inspect-source dist/PPSA99771 --json
ps5-pkgkit verify HelloWorld.pkg
ps5-pkgkit verify HelloWorld.pkg --sha256 "$EXPECTED_SHA256" --json
```

`build` writes a package in the measured debug-package template: the finalized-image header, the outer PFS image, the content container and the install-metadata ZIP. Executables that some dumpers leave malformed are repaired, `param.json` is rewritten (DRM, launch fields, content id, size class) without touching the source, the container carries the presentation assets, the debug license, the PlayGo tables and the scenario, and the result is verified before it replaces the destination.

The inner image is Kraken-compressed by default, with the Python encoder and the block layout descriptor the console's decoder expects. On the recorded Hello World folder this reproduces the reference builder's package byte for byte (same SHA-256), including the reference's build timestamp when `build_package(timestamp=...)` is given one. `--stored` keeps the image uncompressed instead; `--level fast|balanced|smallest` trades compression time for size.

Options: `--content-id` overrides the id from `param.json`, `--firmware 5.10` sets `requiredSystemSoftwareVersion`, and `--language` narrows the PlayGo scenario. Python applications can call `ps5_pkgkit.build_package(source, output, ...)` and catch `ps5_pkgkit.BuildError`.

`inspect-source` checks the base-app identity and source paths, then hashes each file. Its `manifest_sha256` is the SHA-256 of sorted `sha256  ./relative/path` lines. It reads the folder without modifying it. Python applications can call `ps5_pkgkit.inspect_source(path)` and catch `ps5_pkgkit.SourceError`.

The verifier checks the finalized-image and content-container structure, the container header and body checksums, and the title metadata. It reports the whole-file SHA-256. Supply a digest from a trusted source to check every byte of the file, including the filesystem image. These are integrity checks. Console installation and launch are separate hardware results.

Python applications can call `ps5_pkgkit.verify_package(path, expected_sha256=...)` and catch `ps5_pkgkit.VerificationError` for invalid packages. The CLI returns exit status 1 for a build, inspection or verification failure and 2 for a usage error.

The build leaves no output behind on failure: it writes a `.partial` file, verifies it, and only then renames it.

Kraken compression is written for fidelity, not speed: the Hello World image (5.9 MB of logical data) takes about half a minute, and a large title would take much longer in CPython. `--stored` skips it.

See the [reference hardware record](docs/HELLO_WORLD_BASELINE.md), the [implementation plan](IMPLEMENTATION_PLAN.md), and the [third-party notices](THIRD_PARTY_NOTICES.md).
