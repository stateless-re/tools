# Overlord RAT config extractor

Reads the build-time configuration out of Overlord RAT Windows agents: the server, Solana memo settings, agent token, persistence and critical-process flags, mutex, startup name, version and build tag. Overlord's builder injects these with `go build -ldflags "-X ..."`, so they sit in the binary as plain Go strings; the tool finds which string is which by following the order in which `config.Load` reads them.

Write-up: [UAT-12643's Overlord build is stock: it rebuilds byte for byte from the public source, and its Solana lookup is switched off](https://stateless-re.github.io/2026/overlord-uat-12643-stock-build/)

## Usage

```sh
python extract.py AGENT.exe [AGENT2.exe ...]
python extract.py --memo BASE64_MEMO AGENT.exe
```

`--memo` decrypts a Solana memo string you already have (AES-256-GCM, key = SHA-256 of the build's agent token, 12-byte nonce first), the same way the agent does. The tool never contacts the blockchain or anything else.

## Example output (abridged)

```json
[
  {
    "file": "b7dfd524b305f476eebf5fc05c4689ed105df44e66353b0d21212a2192c9c26c",
    "sha256": "b7dfd524b305f476eebf5fc05c4689ed105df44e66353b0d21212a2192c9c26c",
    "go_version": "go1.26.0",
    "build_tags": ["noprint", "persist_startup", "persist_registry"],
    "package": "overlord-client/cmd/agent",
    "gui_subsystem": true,
    "config": {
      "server": "41.216.188.11:5173",
      "server_is_raw_list": "false",
      "solana_enabled": "false",
      "solana_address": "",
      "solana_rpc_endpoints": "",
      "agent_token": "dev-token-insecure-local-only",
      "persistence": "true",
      "critical_process": "false",
      "mutex": "1q_yMrvxBOTfCaitlzClfVyC",
      "agent_version": "2.0.4",
      "sleep_seconds": "0",
      "build_tag": "0a6d1cf8-6aec-4f5e-952b-8d87ea36bda8",
      "startup_name": "Sip",
      "memo_key_sha256_of_token": "36b644fb06bedf6904ca14142239e265254abf0ca35070025220bd2ffc91c3fe"
    },
    "env_overrides": ["OVERLORD_AGENT_TOKEN", "OVERLORD_CAPTURE_INTERVAL", "..."]
  }
]
```

From a 3.2.2 build, later builds add a TLS key pin and a signed build tag whose first segment is decoded:

```json
{
  "agent_version": "3.2.2",
  "tls_spki_pins": "zw2xwVTt9EwEFHZzX3XQvX20LTbw3H2dqbih9AT9pII=",
  "build_tag_decoded": {"v": 1, "bid": "c6ba7103-978c-4d08-b2ef-4552f5cbd5d4", "uid": 1, "iat": 1792918253}
}
```

## How it works

Every `Default*` variable the builder sets with `-X` is a Go string header (pointer, length) in `.data`; variables left empty stay zero in `.bss`. Upstream's `config.Load` reads them in the same source order in every version from 2.0.4 to 3.2.2: server, raw-list flag, Solana flag, Solana address, RPC endpoints, agent token; then persistence, critical process, the public-IP flag and the TLS pins (in later versions); the agent token again; mutex, country, version, build tag and sleep seconds. The tool parses the pclntab to find `*/cmd/agent/config.Load`, disassembles it with capstone, lists each 16-byte header it loads in order, and assigns them by that order. The sleep value is the load right before `config.parseSleepSeconds`; the version is the one shaped like `x.y.z`. The startup name comes from the first load in `persistence.generateBinaryName`. When the pclntab's text start is 0 (Go 1.26+), the function base comes from `moduledata.text`, which matters for externally linked builds where Go's code doesn't start at the beginning of `.text`. Environment variable names (`OVERLORD_*`) are listed when the build still has its run-time overrides; release-builder builds don't.

## Limits

- Garbled builds (the builder's "obfuscate" option) rename functions; the tool reports an error.
- Forks that rewrite `config.Load` may not follow the order. The `spacex1337-client` fork below fails with "second agent token read not found".
- Loaders and wrappers around an agent (MSVC, MinGW, .NET) are not unpacked.

## Tested on

| SHA-256 | Result |
|---|---|
| `b7dfd524b305f476eebf5fc05c4689ed105df44e66353b0d21212a2192c9c26c` | 2.0.4, 41.216.188.11:5173 (the UAT-12643 build in Cisco Talos' IOC list) |
| `cc85777c5439e314484d6314a89164bb7a723ec965246931303a78a0d2c1df35` | 2.3.3, 34xuhusr8a.localto.net:2072 |
| `4320692c3d8740441eddb60c5fece7d15cb5fbb8ca1e4eb7199745223459878a` | 2.3.12, panel.tberat-vac.com |
| `ef1c7270096b4d0dffb394d09416320d12aa24b9d9b70f89998d90e42ac63098` | 3.1.0, default wss://127.0.0.1:5173, critical process on |
| `8b2c1bb8bf0f960821acfcefb3d0707326faaf49bace8f389a9b531145fde100` | 3.2.2 (Go 1.27.3, external linker), weteelectricpower.com |
| `fa86ec228144b089dc8f507f81ddbf7f8bf69fac64c11348e2febea85719f2bb` | fork `spacex1337-client`: error, not supported |
| `f34ccaabd453d1a48109ea8f96b224c845ff03da08059db5ae5c63b3bf21bc15` | probable garbled agent: error "no Go pclntab found" |

For the first build, the values were confirmed against a rebuild of upstream commit b0c88f8 with these settings, which reproduced the file byte for byte.

## Credit and prior work

- Cisco Talos, [UAT-12643: Suspected North Korea-aligned actor blends blockchain resilience with targeted infostealing](https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/) (2026-11-18).
- Proofpoint, [UNK_DeadDrop](https://www.proofpoint.com/us/blog/threat-insight/dont-fear-repo-unkdeaddrop-phishing-campaign-targets-developers-steal) (June 2026), which identified Overlord as an open-source Go framework.
- Source used for comparison: the `doesntbreaktos/Overlord` mirror on GitHub, which keeps the full upstream history (829 commits; the original `vxaboveground/Overlord` repository is gone).
- Checked before writing (2026-11-18): CAPE parsers, GitHub code search, web search. Triage's sandbox extracts the C2 field only (none for the Go 1.27 build); no public tool reads the rest.
