# BubbleLoader unpacker

Unpacks programs patched by BubbleLoader: it follows the entry-point patch to the carrier PNG resource, decrypts stage 2 with the key PNG and stage 3 with its nine-character key, and writes the payload PE. The payload comes out as the builder packed it, before stage 3 randomizes its `int3` padding.

## Usage

```sh
python unpack.py HOST.exe [HOST.exe ...] [-o OUTDIR]
```

## Output (abridged)

```json
{
  "sha256": "e39a78e433f1704f2f5776ef389ec802beb628350691614bfc581d49842aae56",
  "entry_patch": {"copy_src_rva": "0x8984", "copy_size": "0x9121", "stage2_offset": "0x8dec", "sleep_ms": 45000},
  "carrier_resource": {"type": "PNG", "id": 910, "size": 37153, "offset_in_resource": 0},
  "stage2": {
    "key_png_len": 20160,
    "encrypted_len": 16172,
    "stage3_entry": "0x4ed0",
    "gates": {
      "min_tsc": 2000000000000,
      "min_cpus": 4,
      "max_tsc_gap": 400000000,
      "busy_wait_cycles": 4000000000,
      "min_interrupt_time_100ns": 3600000000,
      "peb_being_debugged": true,
      "xor_aa_strings": ["GetLastInputInfo", "user32.dll"]
    }
  },
  "stage3": {"key": "MVMAIYzZp", "key_hex": "4d564d4149597a5a70", "payload_offset": "0x92c", "payload_end": "0x3f2c"},
  "payload": {
    "sha256": "dface52ab8420d2f4c57d99943ba38585fdc4cd4c70f9d84276f701bfbdd34d7",
    "size": 13824,
    "urls": ["https://popularcommunitypic.com/security/updater", "..."]
  }
}
```

## How it works

The entry-point patch copies one resource into RWX memory and jumps into it. The unpacker reads the copy source (`lea rsi, [rbx+imm32]`), the length (`mov ecx, imm32; rep movsb`) and the jump offset (`lea r10, [r10+imm32]; jmp r10`). The copied resource is a valid gradient PNG followed by a fake PNG; stage 2 sits at its tail.

Stage 2 adds three constants to its base: the key length, the encrypted length and the stage-3 entry. It XORs the fake PNG with the whole key PNG, repeating: `stage3[i] = fake[i] ^ K[i % len(K)]`. Two builds first decrypt the rest of stage 2 with a nine-byte XOR key stored between a `jmp` and its target; the unpacker undoes that layer first.

Stage 3 keeps a nine-byte key between `call $+5+n` and the instruction that pops it. The unpacker finds the `lea r10, [rip+x]` that points at the key's end, then the `lea rdx` / `lea r8` pair that bounds the payload, and XORs it with the key. Stage 3 at run time also overwrites runs of ten or more `CC` bytes with `rdtsc` values; static decryption skips that, so the hash is the original one.

The `gates` object lists the checks found in stage 2: `rdtsc` minimum, TSC gap and busy-wait, `PEB.NumberOfProcessors`, `KUSER_SHARED_DATA` InterruptTime, `PEB.BeingDebugged`, and API names encoded with XOR 0xAA.

## Tested on

The 24 hashes from the ReversingLabs report, all from Hybrid Analysis. Payloads match a separate Unicorn emulation of all three stages on every file.

| SHA-256 | Carrier | Stage-3 key | Payload |
|---|---|---|---|
| `053066c7764e8c5c35ef3b44e7c51f0cad0d287adab41966d393c78357c1c917` | PNG 825 | `gWvnMd8bq` | `dface52a` WinRateLoader |
| `07784d651f8d049356a98a433eeb08b4168429f1c4a8bc8d0e597381e57249e8` | PNG 882 | `U1UDulgHU` | `a713022b` WinRateStealer |
| `08c98eb05a9b95a4f934ba67310ff670af63fc057c0c53879592b450b8848cfd` | PNG 268 | `zLNi3YKN5` | `c38bb7a3` exit stub |
| `17a34146fef39ec6a403546364249a574f8add6d40dfc09ee30f8ad478226f15` | PNG 495 | `B1X32kRT1` | `c38bb7a3` exit stub |
| `184f90da785a868dc1439b0796cc2081efc133040f2c4f79cfcc45acfa50089c` | PNG 651 | `HdVRZYVa0` | `b2304c30` WinRateStealer |
| `1e61e1842792d3f790820b3b9268edd22e68e0f43eaedfaf1015f6eaf9ef7c2d` | PNG 718 | `NavFe1MI3` | `a713022b` WinRateStealer |
| `3bde84b2ba4c53ace15695770779383ff788d850cea38d21cb0c6d80e650d710` | PNG 548 | `jJam4cwrG` | `dface52a` WinRateLoader |
| `4987af027009d572c26f6d009c5e53e237cb2e3ab9d52094c14dc0b8b6f40b14` | PNG 795 | `XvBvLCIGu` | `a713022b` WinRateStealer |
| `70ece0d830302898af0df01137b4042b6a039d2ef34f77abbac48a9e73f7674a` | PNG 687 | `qZnla5B4U` | `dface52a` WinRateLoader |
| `776e778dfe8c5c19f1433da60b7f9d0de86a84723e9bfc66bb2b2fd0f98f04bf` | PNG 242 | `uG8TG2epB` | `a713022b` WinRateStealer |
| `8e01f550789617de4605dc5e3288ff51795e88462126dd71ef3ec85f3e318b37` | PNG 288 | `hybkhekLT` | `dface52a` WinRateLoader |
| `a347e678626686a9bb27120df1e92ce98561f60f0f54e2501bcb4648cc41566a` | PNG 986 | `Yzz3jt3GB` | `a713022b` WinRateStealer |
| `aa71f94a01b82617fbc44f6d1727c93cfc9d39727c332681f850bcbce96dc2ae` | PNG 145 | `oaM69ozDd` | `dface52a` WinRateLoader |
| `ad70a492aef847553f771d6fb717541d11e242a83de63f3c0100de76a5ecdff5` | PNG 680 | `ppLfYOXFw` | `a9d01d75` exit stub |
| `c0974e323cb96b77a98c28f7dbc3f00bf8fe421890b2cbfb11b43a7b64fa6c3b` | PNG 357 | `QDno5AzEz` | `a713022b` WinRateStealer |
| `ce86d243904e31d815713351b99e251ce4b415b3df7bb204a9f8b695e9c4b333` | PNG 545 | `QOnXKsl6S` | `a713022b` WinRateStealer |
| `d14c71d924e965af4e98ab8f93b7ffbeb561c7fb37d5280f7146a900a7a0da6f` | PNG 330 | `ULx1gXdzr` | `dface52a` WinRateLoader |
| `d5c8c4e528c659f6b772e16e0e26529c02faf21e46402ec0e97b25d99f801626` | PNG 513 | `zq8vx4Ijg` | `c38bb7a3` exit stub |
| `da84d6ea16251c912e9603ab1f642df2b7178d07db053588f7c1f7ab3df8d4c3` | PNG 497 | `yUlAGwTDU` | `c38bb7a3` exit stub |
| `df11dd7bb354f4b020c8e3bd09f7751fc89d0b764519d7ea2bdc2f5e4d3b15be` | PNG 425 | `x7P1ZeuV3` | `dface52a` WinRateLoader |
| `e39a78e433f1704f2f5776ef389ec802beb628350691614bfc581d49842aae56` | PNG 910 | `MVMAIYzZp` | `dface52a` WinRateLoader |
| `e4b6699c56fe9d3bb1f6492c9c42b0497e546155ac0f81b4994612142f5cb03f` | PNG 259 | `L6XPBMH5Q` | `c38bb7a3` exit stub |
| `f88891995c61bb349c772e8864a4d408d5ed605b59b7b7db581a58601f820029` | PNG 617 | `dBXp1vJa5` | `c38bb7a3` exit stub |
| `fd00db1f4e95aea21083a4eaed555091e39ea3c4200ea79bc856b45f1c2ebb3a` | PNG 333 | `n9LlAzYia` | `dface52a` WinRateLoader |

## Credit

Robert Simmons (ReversingLabs), [Threat Researcher's Notebook: BubbleLoader](https://www.reversinglabs.com/blog/threat-researchers-notebook-bubbleloader), documented the entry-point patch, the PNG pair and the stage-3 loader, and published the hashes.

Write-up: [BubbleLoader's 24 samples carry one stealer, its downloader, or a stub that only exits](https://stateless-re.github.io/2026/bubbleloader-winrate/)
