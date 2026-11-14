# stateless tools

Config extractors and small helpers written while analyzing malware for [stateless](https://stateless-re.github.io). Each one exists because nothing public did the job when it was written.

Everything here is static. The tools parse files; they never run them.

| Tool | What it does | Write-up |
|---|---|---|
| [families/2cloader](families/2cloader) | 2CLoader config extraction and payload decryption | [2CLoader keys its payload to its own padding](https://stateless-re.github.io/2026/2cloader-keys-its-payload-to-its-own-padding/) |
| [families/remus](families/remus) | Remus (x64) C2 slots, Ethereum fallback and build tag | [What 2CLoader delivered: Vidar on Epic Games profiles, Remus on Ethereum](https://stateless-re.github.io/2026/what-2cloader-delivered/) |
| [families/squawkdoor](families/squawkdoor) | SquawkDoor (SquadC) config from MSI installers, payload files or carved images | [SquadC is SquawkDoor, and one of its installers is SparrowDoor](https://stateless-re.github.io/2026/squadc-is-squawkdoor/) |
| [families/antino](families/antino) | Antino config (Microsoft 365 tenant, app, user, remark) from builds or dumps; Gen1 session ID decoding | [Antino's first sleep mask caught every crash in the process](https://stateless-re.github.io/2026/antino-sleep-mask/) |
| [families/nikc2](families/nikc2) | NIK C2 (NIKRAT) agent configs, derived AES keys and certificate pins; unwraps FileCrypt and the PyInstaller binder | [Twenty NIK C2 files, one panel account, and a build that can't read its own config](https://stateless-re.github.io/2026/nik-c2-config/) |
| [samples/ecaa3ca51c1e](samples/ecaa3ca51c1e) | FrauPDF installer: string tables, URLs, embedded files, payload blob and `uid` decoding | [FrauPDF's installer checks its own file name before it asks for a payload](https://stateless-re.github.io/2026/fraupdf-installer/) |

## Layout

- `families/<family>/`: tools that work across builds of one malware family.
- `samples/<first 12 hex of SHA-256>/`: tools for one specific sample, when its format isn't shared by a family.

Each folder has a README with usage, example output, the sample hashes it was tested on, and credit for prior research.

## Running

```sh
pip install pefile cryptography dissect.util olefile dnfile
python families/2cloader/extract.py SAMPLE.exe
```

Python 3.10 or later. Tools print JSON and exit with status 1 if any input fails.

## Conventions

- Plain Python with type hints, formatted and linted with `ruff` (configuration in `pyproject.toml`).
- No comments or docstrings: names and structure carry the meaning, and each folder's README carries the explanation. `checks/no_comments.py` enforces it in CI.
- Command-line interface through `argparse`, so `--help` works for every tool.
- Well-known libraries over reimplementations.

## License

MIT
