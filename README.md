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
| [families/k2f](families/k2f) | k2f LuaJIT bundle (NIKKE launcher): Prometheus string table from any build, modules and build tag | [The NIKKE launcher's k2f agent decrypts the saved login with a key made from the MAC address](https://stateless-re.github.io/2026/k2f-nikke-launcher-bundle/) |
| [families/armorsteal](families/armorsteal) | Armorsteal module config from Pyarmor-Static-Unpack-1shot disassembly: C2 list, package hash pins, task-signing key, clipper wallets, miner pin; XMRig pools including embedded configs | [Armorsteal's Pyarmor key is the shared trial key, and its boot task starts a miner](https://stateless-re.github.io/2026/armorsteal-pyarmor-trial-miner/) |
| [families/xcpe](families/xcpe) | x.cpe (XCPE TV-box botnet): signer and AOSP test-key check, config AES key, hosts and MQTT topics; decodes the hidden MzSDK loader (StringFog, letu.jet core jar, C2 URLs and key); decrypts config and SDK traffic | [Three x.cpe builds hide a second loader, and its string key is "UTF-8"](https://stateless-re.github.io/2026/xcpe-mzsdk-loader/) |
| [families/cerealloader](families/cerealloader) | Turla CerealLoader (C++/CLI mixed-mode .NET loader): payload and log paths, RC4 or key-prefix XOR scheme and key, export-proxy target, VTableFixup slots, the native `CcmEval` string, and the original pre-ConfuserEx metadata (method names, C++ literals, `#US`); decrypts payload files | [Turla's CerealLoader still carries its unobfuscated metadata](https://stateless-re.github.io/2026/cerealloader-original-metadata/) |
| [families/noobsaibot](families/noobsaibot) | NoobSaibotRAT (AgentCore): unpacks the .NET single-file bundle and AES loader, decodes the config (C2, pinned certificate thumbprint, auth token, mutex, flags) | [NoobSaibotRAT's sandbox check averages its evidence, so a machine that fails every test gets through](https://stateless-re.github.io/2026/noobsaibotrat-evasion-average/) |
| [samples/ecaa3ca51c1e](samples/ecaa3ca51c1e) | FrauPDF installer: string tables, URLs, embedded files, payload blob and `uid` decoding | [FrauPDF's installer checks its own file name before it asks for a payload](https://stateless-re.github.io/2026/fraupdf-installer/) |

## Layout

- `families/<family>/`: tools that work across builds of one malware family.
- `samples/<first 12 hex of SHA-256>/`: tools for one specific sample, when its format isn't shared by a family.

Each folder has a README with usage, example output, the sample hashes it was tested on, and credit for prior research.

## Running

```sh
pip install pefile cryptography dissect.util olefile dnfile androguard capstone
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
