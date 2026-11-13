# stateless tools

Config extractors and small helpers written while analyzing malware for [stateless](https://stateless-re.github.io). Each one exists because nothing public did the job when it was written.

Everything here is static. The tools parse files; they never run them.

| Tool | What it does | Write-up |
|---|---|---|
| [families/2cloader](families/2cloader) | 2CLoader config extraction and payload decryption | [2CLoader keys its payload to its own padding](https://stateless-re.github.io/2026/2cloader-keys-its-payload-to-its-own-padding/) |
| [families/remus](families/remus) | Remus (x64) C2 slots, Ethereum fallback and build tag | [What 2CLoader delivered: Vidar on Epic Games profiles, Remus on Ethereum](https://stateless-re.github.io/2026/what-2cloader-delivered/) |

## Layout

- `families/<family>/`: tools that work across builds of one malware family.
- `samples/<first 12 hex of SHA-256>/`: tools for one specific sample, when its format isn't shared by a family.

Each folder has a README with usage, example output, the sample hashes it was tested on, and credit for prior research.

## Running

```sh
pip install pefile cryptography dissect.util
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
