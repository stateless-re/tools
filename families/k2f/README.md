# k2f LuaJIT bundle string decoder

Decodes the string table of the k2f agent, the LuaJIT bundle delivered through the NIKKE PC launcher in October and November 2026, and lists its `package.preload` modules and build tag. The table is Prometheus's ConstantArray step with `Encoding = "mixed"`; the decoder reads every parameter of that step from the bytecode, so it does not depend on one build's alphabets, prefixes, rotation or offset.

Write-up: [The NIKKE launcher's k2f agent decrypts the saved login with a key made from the MAC address](https://stateless-re.github.io/2026/k2f-nikke-launcher-bundle/)

## Usage

```sh
python extract.py BUNDLE [BUNDLE ...]
python extract.py --strings BUNDLE
```

Output is JSON on stdout. `--strings` adds every decoded string keyed by the number the code passes to the accessor, so `F0(47106)` in a disassembly is `strings["47106"]`. Exit status is 1 if any input fails. No third-party packages are needed.

## Example

The bundle `cc0ad05b…` (lists abridged):

```json
{
  "file": "cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec",
  "sha256": "cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec",
  "size": 205135,
  "bytecode": {
    "version": 1,
    "luajit": "2.0",
    "stripped": true,
    "flags": 2,
    "prototypes": 339,
    "consumed": 205135
  },
  "string_table": {
    "prototype": 337,
    "entries": 1790,
    "rotation": [
      [
        1,
        1790
      ],
      [
        1,
        1341
      ],
      [
        1342,
        1790
      ]
    ],
    "prefixes": {
      "base64": "T",
      "base85": "1"
    },
    "accessor_offset": -46736,
    "index_range": [
      46737,
      48526
    ]
  },
  "globals": {
    "K2F_LUA_BUILD": "722b99d8d0e9"
  },
  "build": "722b99d8d0e9",
  "modules": [
    {
      "name": "base64",
      "proto": 6
    },
    {
      "name": "json",
      "proto": 29
    },
    {
      "name": "win32.ffi_defs",
      "proto": 32
    },
    {
      "...": "43 more"
    }
  ],
  "strings_of_interest": [
    "%LOCALAPPDATA%\\Google\\Chrome\\Application",
    "%LOCALAPPDATA%\\Google\\Chrome\\User Data",
    "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\PlatformExperienceHelper",
    "%ProgramFiles%\\Google\\Chrome\\Application",
    "%TEMP%\\k2f-bcreds-",
    "%s\\k2f_screen_%d_%d.jpg",
    "..."
  ]
}```

`strings_of_interest` is a filter over the decoded strings (URLs, CLSID keys, Chrome paths, DLL names, anything containing `k2f`), not a list of indicators: the `hooks.slack.com` URLs, for example, belong to the agent's token detector.

## How it works

The parser reads LuaJIT dump versions 1 (LuaJIT 2.0) and 2 (LuaJIT 2.1), little-endian, stripped or not, and checks every prototype's length so a misparse stops instead of producing garbage. The string table is the largest constant array of strings. In the same prototype, three-slot constant arrays `{nil, a, b}` are the rotation pairs, applied in bytecode order as in-place reversals of `T[a..b]`, and the two hash-only constant tables with 64 and 85 single-character keys mapping to `0..n-1` are the alphabets. The accessor is the four-instruction child function `UGET; ADDVN|SUBVN; TGETV; RET1`, and its constant and opcode give the offset and its sign. Each string starts with one of two prefix characters; the decoder tries both assignments of prefix to encoding and keeps the one whose output is printable. Base64 groups four symbols into three bytes and stops at `=`; base85 groups five symbols into four bytes, pads a short final group with the value 84 and emits one byte less than the group length, and reduces every output byte modulo 256 as the Lua code does.

Modules and globals come from the string-table prototype: a function constant assigned right after a decoded string is a `package.preload` entry, and a `GSET` right after one is a global (`K2F_LUA_BUILD`). That part relies on the bundle's layout; on Prometheus output that also went through its control-flow flattening step (`Cff`), the strings decode but the module and global lists come back empty.

## Tested on

| SHA-256 | File | Result |
|---|---|---|
| `cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec` | k2f bundle, 205,135 bytes (Hybrid Analysis) | 1,790 strings, identical to a second decoder written from the disassembly; 46 modules; build `722b99d8d0e9` |

Synthetic files: one benign Lua script obfuscated three times with Prometheus's Weak preset (commit a98c501, defaults otherwise) and compiled with `luajit -b -s` from LuaJIT 2.0 and 2.1. All strings decode in each.

| SHA-256 | File | Dump version | Prefixes (base64 / base85) | Offset | Second rotation pair |
|---|---|---|---|---|---|
| `f9c52115dea6b1f43decc020dd6031537a02dfcce7766aedf5f07ccc380be721` | `weak1.v1.ljbc` | 1 | `]` / `(` | 23245 | [1, 7] |
| `a0c061743d00ca290e777dd4d4e969571b233960e865a6a00192883cd3070b0f` | `weak1.v2.ljbc` | 2 | `]` / `(` | 23245 | [1, 7] |
| `537ab7e7b1bed75e1c794ad40fe07cb43a5b91988b9e0ab8d58d6f142ea5a7a2` | `weak2.v1.ljbc` | 1 | `?` / `}` | 12189 | [1, 25] |
| `e4daf5c64948324cc30a1929bda14714229b49a45fe064f8936399d46539b48f` | `weak2.v2.ljbc` | 2 | `?` / `}` | 12189 | [1, 25] |
| `3494b15755cab4822678af14d58ad26a3123d6a7cd0ff0930cc86ffbc108afa7` | `weak3.v1.ljbc` | 1 | `+` / `5` | -4010 | [1, 22] |
| `979b52bd75a4d350a80b44e996960a197cc6032e0ee306149f071bbe025c3647` | `weak3.v2.ljbc` | 2 | `+` / `5` | -4010 | [1, 22] |
## Credits

- Bitdefender ([Attackers turn NIKKE's game launcher into malware](https://www.bitdefender.com/en-us/blog/labs/nikke-game-launcher-malware)) reported the bundle and its hash.
- [WormW/nikke_malware_analysis](https://github.com/WormW/nikke_malware_analysis) published the first decoders for this build: `decode_bundle_strings.py` (alphabets in the code) and `lj_bcdump.py`, which reads the array and alphabets from the raw dump but has this build's prefixes, offset and rotation ranges in the code. This decoder also recovers those from the file.
- [MotherSphere's write-up](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5) has the full incident; [Prometheus](https://github.com/prometheus-lua/Prometheus) is the obfuscator (`src/prometheus/steps/ConstantArray.lua`).
