# Antino config extractor

Extracts the Microsoft 365 configuration from Antino backdoor builds (EXE, DLL, x86, x64, or a memory dump with no section table worth trusting) and decodes the session IDs of the October 2025 standalone builds. The client secret is redacted unless you ask for it.

Write-up: [Antino's first sleep mask caught every crash in the process](https://stateless-re.github.io/2026/antino-sleep-mask/)

## Usage

```sh
python extract.py SAMPLE [SAMPLE ...]
python extract.py --show-secret SAMPLE
python extract.py --session BASE64_SESSION_ID
```

Output is JSON on stdout. Exit status is 1 if any input has no config or a session ID doesn't decode.

## Example

The memory image `ca14ad03…` and a session ID made up for testing (not a victim's):

```json
[
  {
    "file": "ca14ad0344dc7216f6da29a5cbe4237d886cc5257e8c3a48fb4885a311c9b800.exe",
    "sha256": "ca14ad0344dc7216f6da29a5cbe4237d886cc5257e8c3a48fb4885a311c9b800",
    "config_source": "scan at file offset 0x377400",
    "config": {
      "tenant_id": "df622d8d-49d3-4dea-9222-a3475dd63ead",
      "client_id": "c381c514-9839-4d24-946c-056607961c23",
      "client_secret": "<redacted, 40 chars>",
      "user_id": "6a9a3baa-7873-43f7-b9b8-a63cf1588302",
      "remark": null,
      "run": false,
      "launch_mode": "exe"
    },
    "build": {
      "machine": "IMAGE_FILE_MACHINE_AMD64",
      "timestamp": "2025-10-17T02:39:26Z",
      "pdb": null,
      "exports": [],
      "markers": {
        "antino_app_manifest": false,
        "rhai_engine": false,
        "retour_hooks": true,
        "session_xor_key": true,
        "thread_suspension_imports": true
      }
    },
    "error": null
  },
  {
    "session_id": "f0pjfHwcK3oLHgo1BwIDcRk5LyoyCyN0MSIWMyExOFgvdnAUTmN0",
    "process_id": "4242",
    "machine_name": "WS-EXAMPLE",
    "username": "analyst",
    "platform": "windows x86_64",
    "fifth_field": ""
  }
]
```

## How it works

Antino keeps its config in a PE section named `.cfg`, 0x10000 bytes, almost all zero. The section starts with a little-endian `u32` length, followed by that many bytes of JSON XORed with `AB CD` repeating. The extractor reads the section when there is one. Otherwise it scans the file for `D0 EF` (`{"` under the key) preceded by a plausible length and keeps the first hit that decodes to JSON with a `tenant_id`. That covers memory dumps like `ca14ad03…`, whose headers are UPX's.

The October standalone builds name a session `Base64(XOR("pid:host:user:platform:field", "KxWNF"))`, standard alphabet with padding. `--session` reverses that. The January builds use a random UUID instead, which carries nothing to decode.

`build.markers` reports strings that separate the builds: the `AntinoApp` manifest, Rhai and `retour` crate paths, the `KxWNF` key, and `Thread32First`, which only the two earliest builds (whose Sleep hooks suspend every other thread) contain.

## Tested on

All from MalwareBazaar; all five return a config.

| SHA-256 | Source of config | Tenant (prefix) | Remark |
|---|---|---|---|
| `09ef7c736bccfafefc44d9910d499173b88063b73b221fc0dc9e9105107e5cff` | `.cfg` section | `8f14bf5c` | `gmail-0326-3` |
| `0c39264337a1186b2e765e24073399cbdcba118306614eb411e315887af578bd` | `.cfg` section | `8f14bf5c` | `mod_sy` |
| `1fadc90b61ce536abda78eb387a7f3d745f00c16775d3f762845ccc0fde567da` | `.cfg` section | `df622d8d` | `gmail` |
| `40e7e77aff603f4c2ef17b3bc8ea836e714d0734a1e5b946e52f95536ec5c91d` | `.cfg` section | `df622d8d` | null |
| `ca14ad0344dc7216f6da29a5cbe4237d886cc5257e8c3a48fb4885a311c9b800` | scan | `df622d8d` | null |

## Credit

Cisco Talos ([UAT-11587 and Antino](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)) for the hashes and the `.cfg` section, and Unit 42 ([Falcon C2](https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/)) for the length-plus-XOR layout and the config field names.
