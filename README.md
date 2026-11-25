# ps5-pkg

A Python library and command-line tool for validating staged PS5 application folders and offline verification of existing packages. The first tested inputs are the Hello World folder and reference package from the native boilerplate.

Install from a checkout with Python 3.11 or newer.

```sh
python -m pip install .
uv tool install .
```

```sh
ps5-pkg inspect-source dist/PPSA99771
ps5-pkg inspect-source dist/PPSA99771 --json
ps5-pkg verify HelloWorld.pkg
ps5-pkg verify HelloWorld.pkg --sha256 "$EXPECTED_SHA256" --json
```

`inspect-source` checks the base-app identity and source paths, then hashes each file. Its `manifest_sha256` is the SHA-256 of sorted `sha256  ./relative/path` lines. It reads the folder without modifying it. Python applications can call `ps5_pkg.inspect_source(path)` and catch `ps5_pkg.SourceError`.

The verifier checks the finalized-image and content-container structure, the container header and body checksums, and the title metadata. It reports the whole-file SHA-256. Supply a digest from a trusted source to check every byte of the file, including the filesystem image. These are integrity checks. Console installation and launch are separate hardware results.

Python applications can call `ps5_pkg.verify_package(path, expected_sha256=...)` and catch `ps5_pkg.VerificationError` for invalid packages. The CLI returns exit status 1 for an inspection or verification failure and 2 for a usage error.

Package creation remains pending. The tested reference package uses a patched authentication path, so this CLI does not write a console-installable `.pkg`.

See the [reference hardware record](docs/HELLO_WORLD_BASELINE.md) and the [implementation plan](IMPLEMENTATION_PLAN.md).
