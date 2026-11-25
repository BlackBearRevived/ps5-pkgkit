# ps5-pkg

A Python library and command-line tool for offline verification of existing PS5 application packages. The first tested input is the Hello World reference package from the native boilerplate.

Install from a checkout with Python 3.11 or newer.

```sh
python -m pip install .
uv tool install .
```

```sh
ps5-pkg verify HelloWorld.pkg
ps5-pkg verify HelloWorld.pkg --sha256 "$EXPECTED_SHA256" --json
```

The verifier checks the finalized-image and content-container structure, the container header and body checksums, and the title metadata. It reports the whole-file SHA-256. Supply a digest from a trusted source to check every byte of the file, including the filesystem image. These are integrity checks. Console installation and launch are separate hardware results.

Python applications can call `ps5_pkg.verify_package(path, expected_sha256=...)` and catch `ps5_pkg.VerificationError` for invalid packages. The CLI returns exit status 1 for a failed verification or file error and 2 for a usage error.

See the [reference hardware record](docs/HELLO_WORLD_BASELINE.md) and the [implementation plan](IMPLEMENTATION_PLAN.md).
