# Armorsteal

Prints the configuration of Armorsteal's Python modules (C2 list, package hash pins, task-signing key, screenshot XOR key, miner pin, monitoring-tool list, clipper wallets, endpoints) from the disassembly that [Pyarmor-Static-Unpack-1shot](https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot) writes. It also reads the Pyarmor header of the obfuscated scripts and the pools and wallets of XMRig configs, including configs compiled into an `xmrig.exe`.

Write-up: [Armorsteal's Pyarmor key is the shared trial key, and its boot task starts a miner](https://stateless-re.github.io/2026/armorsteal-pyarmor-trial-miner/)

## Usage

Decrypt first with 1shot (static; it never imports the scripts):

```sh
python Pyarmor-Static-Unpack-1shot/oneshot/shot.py Update/ -o dec/
python families/armorsteal/extract.py dec/SysMon.py.1shot.das dec/xm_handler.py.1shot.das
python families/armorsteal/extract.py Update/SysMon.py xmrig-6.26-v2-cs-2.zip configf.json
python families/armorsteal/extract.py --das-only dec/
```

Requires `cryptography`. Inputs that are neither 1shot disassembly, a Pyarmor script nor an XMRig config produce an `error` record and exit status 1.

## Output (abridged)

```json
[
  {
    "file": "xm_handler.py.1shot.das",
    "kind": "pyarmor-1shot-das",
    "module": "xm_handler",
    "config": {
      "DOMAINS": [["workerstats.net", "443"], ["niceer.net", "443"], ["datamons.org", "443"], ["supertrap.net", "443"]],
      "XMRIG_ZIP_NAME": "xmrig-6.26-v2-cs-2.zip",
      "XMRIG_ZIP_HASH": "4a39f7a37ef2f81e6e75ec7dd931392b49dd3016ff8ede651f57e9344b1eeb4e",
      "DEFENDER_EXCLUSION_PATH": "C:\\Windows",
      "MONITORING_TOOLS": ["anvir.exe", "autoruns.exe", "autoruns64.exe", "..."]
    },
    "c2": ["workerstats.net:443", "niceer.net:443", "datamons.org:443", "supertrap.net:443"],
    "endpoints": ["/downloadables/"],
    "urls": []
  },
  {
    "file": "SysMon.py",
    "sha256": "0ea99fbbe29af6f797e3866ed5f822c7a5d3e9cdb990a8c382a715069f156499",
    "kind": "pyarmor-script",
    "pyarmor_version": "9.1.7",
    "edition": "trial",
    "serial": "000000",
    "product": "non-profits",
    "obfuscated_at": "2026-09-16T21:43:47.262326",
    "trial_key": true
  }
]
```

For `SysMon.py` disassembly the record adds `VERIFIED_HASHES` and `task_signing_key` (bits, exponent, modulus prefix, SPKI SHA-256); for `basrq.py`, `screenshot_xor_key` and `clipper_wallets`; for XMRig inputs, `pools`, `worker_id` and the file offset of an embedded config.

## How it works

Armorsteal keeps its settings in module-level assignments (`DOMAINS = [...]`, `VERIFIED_HASHES = {...}`, `FIXED_PASSWORD = '...'`). The extractor walks the top-level code object's instructions in the 1shot disassembly and replays the few opcodes that build constants (`LOAD_CONST`, `BUILD_LIST`/`BUILD_SET` with `LIST_EXTEND`/`SET_UPDATE`, `BUILD_CONST_KEY_MAP`) up to each `STORE_NAME`, so it gets the values the module binds instead of guessing from a string dump. Clipper wallets are the constants of `monitor_clipboard` that match the malware's own address patterns. `trial_key` is true when the license number is `000000`: Pyarmor's trial runtime derives its AES key from license data that carries nothing about the user; for the runtimes tested (8.4.7 to 8.5.1) it equals the default key 1shot ships, so these scripts decrypt even without their runtime.

## Tested on

| SHA-256 | file | result |
|---|---|---|
| `3e3b62a9836697d978cbb620dc8af8f6eefdf8cb73fc30d16bb394d1c58f4c97` | `Update.zip` (Sept 16): `SysMon.py`, `xm_handler.py` | config, hash table, key |
| `d89ba5767848eb5597d03a1d0ae30cc451050859fbc3b9fd3095a9474dd7d86b` | `Update.zip` (Sept 1): `SysMon.py` | config, older hash table |
| `237ba698d7dc8936c43e0e78e7644002375e51e8baf9b3a7d4e18683f871ee31` | `nig20084.zip`: `basrq.py` | C2, XOR key, 13 wallets |
| `be0329d0795dd62ae587faf97e704bb36413e5c98ddd8fe575f5077db3c84e5f` | `getthem20084.zip`: `got.py` | C2, endpoints, URLs |
| `253653f645b9c89e7e7e7e967926b0cf0f9adda98ac9d6ba4aa1eb354d80ab9d` | `xmrig6.26-v2.zip` | 3 pools, wallet |
| `4a39f7a37ef2f81e6e75ec7dd931392b49dd3016ff8ede651f57e9344b1eeb4e` | `xmrig-6.26-v2-cs-2.zip` | embedded config, 4 pools, wallet |
| `8591e3a176aa082faaae9f19882c62dd8e120ee5c269a1402b9d826999251d7e` | `configf.json` | 3 pools, wallet |

## Credit

Zscaler Threat Hunting (Nashid P) named and described [Armorsteal](https://www.zscaler.com/blogs/security-research/seo-poisoning-campaign-delivers-new-armorsteal-malware). Decryption is entirely [Pyarmor-Static-Unpack-1shot](https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot) by Lil-House; G DATA documented the format in [Unpacking Pyarmor v8+ scripts](https://cyber.wtf/2025/02/12/unpacking-pyarmor-v8-scripts).
