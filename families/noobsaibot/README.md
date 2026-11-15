# NoobSaibotRAT

Static config extractor for NoobSaibotRAT (internal name AgentCore), a .NET 8 RAT and stealer. It accepts the .NET single-file bundle, the AES loader assembly (`System Process.dll`) or the AgentCore assembly itself, and prints the C2 host and port, pinned certificate thumbprint, auth token, mutex, persistence name and feature flags, plus the per-build junk `ai_` fields and the hashes of the app files inside the bundle.

Write-up: [NoobSaibotRAT's sandbox check averages its evidence, so a machine that fails every test gets through](https://stateless-re.github.io/2026/noobsaibotrat-evasion-average/)

## Usage

```sh
python extract.py FILE [FILE ...]
python extract.py BUNDLE.exe -o outdir
```

`-o` writes the decrypted AgentCore assembly to `outdir`, named by its SHA-256, mode 600. Nothing is loaded or run. Exit status is 1 if any input yields no AgentCore config.

Requires `pefile`, `dnfile` and `cryptography`.

## Output (abridged, older build `63a9dd2e`)

```json
{
  "role": "agent",
  "sha256": "63a9dd2ea552fbb84afdec77884f88cc3dc86c26c257a23c465905f218c5d27e",
  "obfuscator_key": "NoobSaibot",
  "config": {
    "ServerHost": "192.52.242.73",
    "UseTLS": true,
    "ServerCertificateThumbprint": "E5C3774B55EE3002093D8D5223A805C4B434E9FD",
    "AuthToken": "0KTtAYlDISW7JJjoe1FaXCe5YNaN0896",
    "PersistenceName": "SystemHealthCheck",
    "StartupDelay": 1000,
    "MutexName": "Global\\{A1B2C3D4-E5F6-7890-1234-56789ABCDEF0}",
    "EnableWMIPersistence": false,
    "EnableAIEvasion": true,
    "ServerPort": 4445
  }
}
```

For a bundle the output also has a `bundle` record (manifest version, bundle ID, file count, main assembly, SHA-256 of each package file listed in `deps.json`) and a `loader` record (resource name, AES key, payload hash).

## How it works

- Bundle: the .NET host stores the bundle manifest's offset in the 8 bytes before a fixed 32-byte signature. The manifest lists every file with offset, size and compressed size; the main assembly is the one named like the `.runtimeconfig.json` entry.
- Loader: the only manifest resource is `IV (16 bytes) || AES-256-CBC(PKCS7)`. The key is a user string padded or cut to 32 bytes. The tool tries each user string until the plaintext starts with `MZ`.
- AgentCore: the tool walks the IL of `AgentConfig`'s static constructor, tracking `ldstr`, `ldc.i4*`, calls to `Obfuscator.Deobfuscate` and `stsfld`. `Deobfuscate` is Base64 then XOR with the UTF-8 bytes of the key it loads with `ldstr` (`NoobSaibot` in both known builds).

## Tested on

| SHA-256 | File | Result |
|---|---|---|
| `9c21d2e50468272329df31911ae3737e7b74a2db5ce33f5e0beccd36582d89c8` | single-file bundle | 208.64.33.85:4443 |
| `0db860c62ce8c95ae3018ef4ded4711bc212d9bd54d4da1063da18790dbecac8` | loader `System Process.dll` | 208.64.33.85:4443 |
| `2b43a7225c4c4e4912cc7cfffac04356b84ee0c5bdceed4d32c6d0111d4bfa58` | AgentCore from the loader | 208.64.33.85:4443 |
| `63a9dd2ea552fbb84afdec77884f88cc3dc86c26c257a23c465905f218c5d27e` | AgentCore, older build | 192.52.242.73:4445 |

## Credits

Threatray named the family in [Threatray Tuesday, 2026-10-13](https://github.com/threatray/threat-research/blob/main/ThreatrayTuesday/iocs-2026-10-13.md). The bundle layout follows Microsoft's [single-file bundler design](https://github.com/dotnet/designs/blob/main/accepted/2020/single-file/bundler.md).
