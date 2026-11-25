# ps5-pkg implementation plan

## First release

A developer with a compiled homebrew title folder can use one command to produce a PS5 base-app `.pkg` and another to verify it offline. Python owns the reader, layout planner and writer. A Python application can import the same operations the CLI calls. The first end-to-end acceptance test is installing the generated package on the test PS5 and launching the boilerplate's Hello World app.

The initial input is a local folder containing one title. Updates, DLC, image conversion, remote transfer and installation automation can be considered after base-app compatibility is demonstrated. Keep the new tool in this repository. The boilerplate becomes a consumer of a tagged version once the writer passes its hardware gate.

Use each checkbox to track work. Close a milestone by linking its commit or CI run and the evidence named in its acceptance criterion. Record the tested firmware and artifact digest alongside every hardware result.

## 1. Establish a compatibility baseline

- [ ] Build Hello World from a recorded boilerplate commit. Record the title ID, content ID, content version and a SHA-256 manifest of the staged folder. Exercise the existing folder build on the test console to establish a working control.
- [ ] Use an independent reference packager on that same staged folder. Record its revision, settings, warnings, package digest and inspection results. Keep a small redistributable fixture and an inventory of its expected files.
- [ ] Resolve the two known readiness questions with this control. The boilerplate supplies `icon0.png` and two DDS backgrounds. The reference checker also looks for `icon0.dds` and `sce_sys/about/right.sprx`. Record which findings affect package creation, installation or launch. If extra artwork is needed, generate it from the project's own asset.
- [ ] Install and launch the control package in the existing homebrew test environment. Confirm the title identity, visible Hello World screen and access to the bundled banner asset. Record the environment actually tested, screen capture and available app logs. Firmware 6.02 is the initial candidate from previous boilerplate testing.

**Acceptance.** A known-working reference package and its source manifest let us distinguish writer defects from title or console compatibility issues. If the control fails, record the failing stage and error before judging Python output against it.

## 2. Define the library and CLI contract

- [ ] Add `pyproject.toml`, an importable `ps5_pkg` package and the `ps5-pkg` console entry point. Choose the supported Python floor after checking dependency and wheel support on Linux, Windows and macOS.
- [ ] Expose `build_package(source_dir, output_path)` and `verify_package(path)`. Return structured results with title metadata, warnings, failures and output size. Keep CLI formatting and exit codes in the CLI layer.
- [ ] Implement `ps5-pkg build TITLE_FOLDER --output FILE.pkg` and `ps5-pkg verify FILE.pkg`. Include path-specific diagnostics and documented nonzero exit codes. Leave an existing destination intact on failure.
- [ ] Validate root `eboot.bin`, readable `sce_sys/param.json`, identity fields and supported title type. Define consistent handling of case collisions, traversal, symlinks, empty files and directories. Exercise Unicode paths on every supported OS.

**Acceptance.** Tests invoke the installed command and import the library from outside the checkout. Both interfaces report the same validation outcomes, and scanning preserves the source manifest.

## 3. Build the reader and verification fixtures

- [ ] Document the base-app layout observed in the reference fixture. Map the package header, filesystem image, metadata entries, presentation assets, PlayGo information and integrity records to named Python data structures. Cite the origin of each format assumption.
- [ ] Implement bounded reads, explicit byte order, section ranges and alignment checks. Check offsets and sizes against the actual file before allocating or seeking. Report unsupported format variants explicitly.
- [ ] Read title identity and enumerate the logical app files. Verify the format's integrity records, then compare app file sizes and digests with the fixture manifest. Document any expected differences between folder metadata and packaged metadata.
- [ ] Add fixtures for truncated input, overlapping or out-of-range sections, altered data and duplicate paths. Include a reference-generated package in the test corpus where redistribution permits, or document how to regenerate it from project-owned inputs.

**Acceptance.** The reader independently validates the reference fixture and identifies the failing check for each damaged fixture.

## 4. Implement the standalone writer

- [ ] Create a stable file inventory and a layout plan containing directories, file extents, metadata, padding and final size. Unit-test the plan with empty, single-file and block-boundary cases.
- [ ] Implement the filesystem-image writer and package container for the base-app profile demonstrated in milestone 1. Carry through the entry executable, runtime module, app assets and title identity. Generate the metadata and integrity records required by that profile.
- [ ] Establish which block storage or compression profile works with the control. Implement that profile first. Where a native codec dependency is warranted, confirm its license, wheel availability and output compatibility before adopting it.
- [ ] Stream bulk data and update hashes incrementally. Write to a temporary file next to the destination, close it, run the reader's verification and publish the completed output. Test cancellation, short writes, insufficient space and a pre-existing output.
- [ ] Read the result with the independent reference reader as well as our own. Compare the logical file manifest and identity fields with the control. Account for variable fields such as timestamps before comparing binary output.

**Acceptance.** A clean Python environment produces a reference-readable package from the boilerplate folder. Verification succeeds, every expected payload file is accounted for, and interrupted builds preserve previous output.

## 5. Validate hardware compatibility and performance

- [ ] Build once in CI, record the SHA-256 and test that exact artifact on the PS5. Verify installation, home-screen title and icon, launch, bundled asset access, clean exit and relaunch. Record results separately for each firmware tested.
- [ ] Compare the Python-built and reference-built packages when a test fails. Track whether the first divergence occurs during host verification, console installation or application launch.
- [ ] Benchmark build time, verification time, peak memory, scratch space and output size on Hello World and a larger synthetic title. Include one large file and a tree of many small files. Publish the input sizes and host details with the results.
- [ ] Check that a tenfold increase in the size of a single asset does not produce a comparable increase in peak process memory. Profile any bottleneck before adding multiprocessing or native acceleration.

**Acceptance.** The hardware record identifies the successful package by digest, and benchmark results quantify the cost of building and verifying it.

## 6. Distribute the tool and integrate the boilerplate

- [ ] Run unit tests and end-to-end CLI tests in GitHub Actions on the supported OS and Python matrix. Build the wheel and source distribution from a clean checkout. Test the wheel itself in fresh environments.
- [ ] Exercise three user paths against the same release wheel: `python -m pip install <wheel>`, `uv tool install <wheel>` and a one-shot `uvx --from <wheel> ps5-pkg` invocation. Run both build and verify after installation and document copyable examples with the actual wheel URL.
- [ ] Attach the tested wheel, source distribution and checksums to a versioned GitHub Release. Set up build provenance and verify it against the workflow and commit wherever supported by the repository's visibility and account plan. Keep release access consistent with repository visibility. Public PyPI distribution is a separate publication decision.
- [ ] After the hardware gate, add an opt-in target in the boilerplate that calls a pinned release of this CLI on `dist/<TITLE_ID>/`. Have its release workflow verify the resulting `.pkg` and attest that artifact against the boilerplate commit. Test the folder ZIP flow alongside it.

**Acceptance.** A developer can follow the release instructions on a clean host and produce a verified package. The release record connects the CLI version, boilerplate revision, tested package digest and hardware result.

## Reference implementations and fixtures

- PS5Upload revision reviewed for its host-side conversion flow, independent reader and round-trip tests. [Package crate](https://github.com/phantomptr/ps5upload/tree/4174eee2319d45a488c37832a5b890de2f9c5358/engine/crates/ps5upload-fpkg)
- Native boilerplate revision used in the initial folder inspection. Record the actual revision for each subsequent test. [Boilerplate build output](https://github.com/BlackBearRevived/ps5-native-app-boilerplate/blob/f5b6c9708351b35d1987e43c2ee8103daeadce57/docs/RELEASE_ZIP.md)
- Existing model for wheel-based installation and one-shot execution. [AT9 converter installation guide](https://github.com/BlackBearRevived/ps5-at9-converter#install-or-run)
