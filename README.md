<div align="center">

# PS5 PKG Kit

Build, inspect, and verify PlayStation 5 homebrew packages from staged title
folders in pure Python.

[![Build](https://github.com/BlackBearRevived/ps5-pkgkit/actions/workflows/ci.yml/badge.svg)](https://github.com/BlackBearRevived/ps5-pkgkit/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/BlackBearRevived/ps5-pkgkit)](https://github.com/BlackBearRevived/ps5-pkgkit/releases/latest)
[![License: GPL v3+](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)

</div>

> [!NOTE]
> The Hello World reference package was installed and launched on PS5 hardware.
> See the [reference record](docs/HELLO_WORLD_BASELINE.md) for the hardware and
> host checks. Report problems through
> [GitHub issues](https://github.com/BlackBearRevived/ps5-pkgkit/issues).

## Project foundations

PS5 PKG Kit implements the reference debug-package format in Python, including
the content container, filesystem images, install metadata, and Kraken
compression. The runtime uses only the Python standard library. The first
tested inputs were the Hello World folder and reference package from the
[PS5 Native App Boilerplate](https://github.com/BlackBearRevived/ps5-native-app-boilerplate).

## Features

- Build a package from a staged base-app folder with one command.
- Inspect the source without modifying it and report a deterministic SHA-256
  inventory of its files.
- Compress the inner image with Kraken by default, or store it uncompressed
  with `--stored` for a faster build.
- Override the content ID, minimum firmware version, or PlayGo language.
- Verify package structure, container checksums, and title metadata. Supply a
  trusted SHA-256 to verify the whole file.
- Build, inspect, and verify directly from the `ps5_pkgkit` Python API.

## How it works

1. **Inspect.** Check the base-app identity and relative paths, then hash the
   staged files. The manifest hashes sorted `sha256  ./relative/path` lines.
2. **Prepare.** Select files for the package, normalize affected executables,
   and rewrite the packaged copy of `sce_sys/param.json`. The staged files
   stay intact.
3. **Assemble.** Plan the inner filesystem image, optionally compress it, and
   write the outer image, finalized-image header, content container, and
   install-metadata ZIP.
4. **Verify and write.** Write to a `.partial` file and verify it before
   moving it into place. The builder removes the partial file on failure.

See the [implementation plan](IMPLEMENTATION_PLAN.md) for format and build
details.

## Install or run

The CLI supports Python 3.11 or newer on Windows, Linux, and macOS. Sign in to
the GitHub CLI with an account that can access the repository, then download
the wheel and release checksums.

```bash
gh release download v0.1.0 -R BlackBearRevived/ps5-pkgkit -p '*.whl' -p SHA256SUMS.txt
sha256sum -c --ignore-missing SHA256SUMS.txt
```

The build examples use a staged title folder named `PPSA99771`.

### Run once with uvx

```bash
uvx --from ./ps5_pkgkit-0.1.0-py3-none-any.whl ps5-pkgkit build PPSA99771 -o HelloWorld.pkg
```

### Install with uv

```bash
uv tool install ./ps5_pkgkit-0.1.0-py3-none-any.whl
ps5-pkgkit build PPSA99771 -o HelloWorld.pkg
```

### Install with pip

Create a virtual environment with `python -m venv .venv`. Activate it with
`source .venv/bin/activate` on Linux or macOS, or
`.\.venv\Scripts\Activate.ps1` in Windows PowerShell.

```bash
python -m pip install ./ps5_pkgkit-0.1.0-py3-none-any.whl
ps5-pkgkit build PPSA99771 -o HelloWorld.pkg
```

You can also install from a local checkout with `python -m pip install .`.

### Download and run the zipapp

```bash
gh release download v0.1.0 -R BlackBearRevived/ps5-pkgkit -p ps5-pkgkit.pyz -p SHA256SUMS.txt --skip-existing
sha256sum -c --ignore-missing SHA256SUMS.txt
python ps5-pkgkit.pyz build PPSA99771 -o HelloWorld.pkg
```

From a clone of this repository, `python ps5pkgkit.py` runs the same command.
After installation, `python -m ps5_pkgkit` also works.

## Options

| Command | Option | Default | Purpose |
| --- | --- | --- | --- |
| `build`, `inspect-source` | `SOURCE` | required | Staged title folder containing `eboot.bin` and `sce_sys/param.json`. |
| `build` | `-o`, `--output FILE` | required | Destination package. |
| `build` | `--content-id ID` | source metadata | Override the package content ID. |
| `build` | `--firmware VERSION` | source metadata | Set the minimum firmware version, for example `5.10`. |
| `build` | `--language CODE` | title metadata or fallback | Select a single PlayGo language. |
| `build` | `--stored` | off | Store the inner image uncompressed. |
| `build` | `--level LEVEL` | `balanced` | Choose `fast`, `balanced`, or `smallest` for Kraken compression. |
| `build` | `--jobs N` | `1` | Use up to N worker processes for Kraken compression. One runs serially. Stored builds skip this step. |
| `verify` | `PACKAGE` | required | Package file to verify. |
| `verify` | `--sha256 SHA256` | none | Compare the whole file with a trusted SHA-256. |
| All subcommands | `--json` | off | Print a machine-readable report. |

```bash
ps5-pkgkit inspect-source PPSA99771 --json
ps5-pkgkit build PPSA99771 -o HelloWorld.pkg --jobs 4
ps5-pkgkit verify HelloWorld.pkg
ps5-pkgkit verify HelloWorld.pkg --sha256 "$EXPECTED_SHA256" --json
```

The CLI exits with status 1 for a build, inspection, or verification failure
and status 2 for a usage error. Python callers can use `build_package()`,
`inspect_source()`, and `verify_package()` from `ps5_pkgkit` and catch
`BuildError`, `SourceError`, or `VerificationError`, respectively. For parallel builds
from a Python script, call `build_package(..., jobs=4)` inside an
`if __name__ == "__main__":` guard so worker processes can import the script.

## Validation

- **Reference parity.** The published wheel reproduced the 17,906,702-byte
  Hello World reference package byte for byte when `build_package(timestamp=...)`
  reused the reference ZIP timestamp. The default CLI uses the current time
  for those fields.
- **Package integrity.** The verifier checks the finalized-image and content
  container structure, header and body checksums, and title metadata. It
  reports the whole-file SHA-256 and compares it when given a trusted digest.
- **Hardware.** The [Hello World reference record](docs/HELLO_WORLD_BASELINE.md)
  documents installation, launch, and checks against the mounted files.

## Source layout

| Path | Purpose |
| --- | --- |
| `ps5pkgkit.py` | Command-line entry point from a checkout. |
| `src/ps5_pkgkit/cli.py` | CLI commands and argument handling. |
| `src/ps5_pkgkit/build.py` | Package build pipeline and output verification. |
| `src/ps5_pkgkit/source.py` | Staged folder validation and file inventory. |
| `src/ps5_pkgkit/verification.py` | Package structure and integrity checks. |
| `src/ps5_pkgkit/format/` | Package, filesystem, and compression format code. |
| `tests/` | Unit, reference parity, and end-to-end build tests. |
| `tools/` | Reference comparison and inspection tools. |
| `docs/` | Reference package and hardware validation records. |

## Development

```bash
python -m pip install -e .
python -m unittest discover -s tests
```

For the reference tests, put `PPSA99771/` and `PS5-PKG-Hello-World.pkg` in
`.artifacts/hello-world/` or set `PS5_PKGKIT_REFERENCE` to their directory.
Build a wheel and source distribution with `python -m build` after installing
the `build` package.

## Releases

GitHub Actions runs the unit tests and a build-and-verify smoke test on Windows,
Linux, and macOS. Version tags such as `v0.1.0` publish the wheel, source
distribution, source ZIP, zipapp, and `SHA256SUMS.txt`. See the
[latest release](https://github.com/BlackBearRevived/ps5-pkgkit/releases/latest).

## Limitations

- The builder targets staged PS5 base applications with `applicationCategoryType`
  set to `0` and `applicationDrmType` set to `free` in the source metadata.
- Kraken compression prioritizes reference parity. The Hello World inner image
  takes about half a minute to compress serially in CPython. Use `--jobs N`
  to compress blocks in parallel or `--stored` to skip compression.
- Host verification checks package integrity. Hardware results are recorded
  separately in the reference record.

## Credits

Thanks to phantomptr for [PS5Upload](https://github.com/phantomptr/ps5upload).
Its package builder inspired this Python implementation and provided the
reference used to check its output.

The upstream revision, ported components, and their licenses are documented in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## License

Copyright (C) 2026 BlackBearReloaded. PS5 PKG Kit is licensed under
GPL-3.0-or-later. See [LICENSE](LICENSE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Disclaimer

PS5 PKG Kit is an independent homebrew project. PlayStation and PS5 are
trademarks of Sony Interactive Entertainment. The software is provided as is
under the GPL's warranty terms.

## AI assistance

OpenAI Codex assisted with development and documentation.
