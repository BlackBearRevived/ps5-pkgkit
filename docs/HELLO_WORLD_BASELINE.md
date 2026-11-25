# Hello World reference baseline

## Source and build

The folder was built in WSL from boilerplate commit `f5b6c9708351b35d1987e43c2ee8103daeadce57`. The build used the standard Hello World sources and presentation assets. A temporary checkout supplied a distinct test identity because the console already had a different build registered as `PPSA99999`. The test ID was vacant in the folder, title and sandbox directories before the run. [Boilerplate source](https://github.com/BlackBearRevived/ps5-native-app-boilerplate/tree/f5b6c9708351b35d1987e43c2ee8103daeadce57)

| Field | Value |
| --- | --- |
| Title | PS5 PKG Hello World |
| Title ID | `PPSA99771` |
| Content ID | `UP9000-PPSA99771_00-PKGHELLOWORLD001` |
| Content version | `01.000.000` |
| Staged files | 8 |
| Source manifest SHA-256 | `faf30c49f4f06010340ed7f0596149c7f21dd923293787c6bd6cc0b5412cac4e` |

The [source manifest](hello-world-source.sha256) lists the exact files fed to the reference packager. All eight source hashes still matched after packaging.

## Host package validation

PS5Upload revision `4174eee2319d45a488c37832a5b890de2f9c5358` supplied the reference builder and reader examples. The builder used its defaults and the output stem `PS5-PKG-Hello-World`. It took the content ID from the staged metadata. [Pinned PS5Upload source](https://github.com/phantomptr/ps5upload/tree/4174eee2319d45a488c37832a5b890de2f9c5358/engine/crates/ps5upload-fpkg)

| Check | Result |
| --- | --- |
| Package size | 17,906,702 bytes |
| Package SHA-256 | `f4746fdf4c66f4e8f664ae5f50bd1ecdca2b741bc9e8647c7ca1070664abae09` |
| Builder read-back | 50 checks passed |
| Separate verifier invocation | Passed |
| Extraction and comparison | All eight expected files present. Title ID, content ID, version, title name, banner and presentation assets matched. |

The reference builder rewrote `eboot.bin`, `sce_module/libc.prx` and `sce_sys/param.json` in the package. The extracted banner, PNG, DDS backgrounds and audio were byte-identical to their source files. The builder warned about the missing `sce_sys/icon0.dds` and `sce_sys/about/right.sprx`. Both warnings were compatible with a successful host build and read-back. Their effect on console installation and launch remains open.

## Console status

The first preflight reached the console's folder deployment service. A different title, `PPSA99006`, was running, and the PS5Upload package installer and helper ports refused connections. Both the folder launch and package install tests remain pending. Firmware for this run has yet to be confirmed.
