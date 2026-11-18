# BotHelper RAT

Static extractor for the BotHelper RAT chain that Point Wild's Lat61 team reported in September 2026: a MinGW x64 stager that downloads an XOR-encrypted `payload.bin`, and the .NET Framework RAT inside it. It prints the stager's download URL and XOR parameters, the RAT's config (C2 base URL, group, version, mutex, persistence and unused install paths, the embedded self-signed certificate), its command and flood names, and decrypts a `payload.bin` container into the decoy and the RAT.

Write-up: [BotHelper's anti-VM switch is never turned on, and its NetTask command is a flood kit](https://stateless-re.github.io/2026/bothelper-paradoxnet/)

## Usage

```sh
python extract.py STAGER.exe RAT.exe
python extract.py --payload payload.bin -o outdir
python extract.py --payload payload.bin --seed 0xA7 --multiplier 31
```

Without `--payload` the tool decides by the file: a PE with a CLR header is parsed as the RAT, any other PE as the stager. `--payload` decrypts and splits the container; if the payload is a PE it is also parsed as the RAT. `-o` writes the payload and any decoy to `outdir`, named by SHA-256, mode 600. Nothing is loaded or run. Exit status is 1 if any input fails.

Requires `pefile`, `dnfile` and `cryptography`.

## Output (abridged)

```json
[
  {
    "sha256": "0d41ce75da4f3404734358411a72ffc4169376dcfebda52ac50eb66eac73d2f6",
    "role": "rat",
    "config": {
      "host": "https://easyllms.xyz/f10c24902875d97a8fef69a3b3a7b5aafb835b7bbfad749c3c161296c745867ea831d7f0133f2f819cd602b3a4b5e41a3dd69024533d8da49cefdd907cc126ed",
      "version": "v1.6",
      "Group": "ParadoxNet",
      "Mutex": "vyub75665ANKiuf78",
      "WatchDogPath": "C:\\Users\\<user>\\AppData\\Local\\CrashDumps\\Crash.exe",
      "AdminPath": "C:\\Windows\\Performance\\WinSAT\\issas.exe",
      "NonAdminPath": "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\HTML Help\\unsecapp.exe"
    },
    "certificate": {
      "subject": "CN=easyllms.xyz,O=ParadoxNet,ST=State,C=EU",
      "serial": "49160F0826D59B8014710A152FB62975C525AEA1",
      "not_before": "2026-09-10T20:50:57+00:00",
      "sha256": "a3328b66cc13105e5b5b5d7627d6633123cb665e377b25aa3da70ae0ffa459b8"
    },
    "net_tasks": ["NetTaskA", "NetTaskB", "...", "NetTaskK", "NetTaskStop"],
    "anti_vm_flag_ever_set": false,
    "config_fields_never_read": ["AdminPath", "Certificate", "NonAdminPath", "hosts"],
    "clr_32bit_required": true
  },
  {
    "sha256": "8f39fe882e45dfa8a7446d59dfef86b583a868ff846ade86124a57041f5c63fd",
    "role": "stager",
    "url": "https://easyllms.xyz/f10c2490...07cc126ed/uploads/Files/payload.bin",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "xor_seed": 167,
    "xor_multiplier": 31,
    "drop_name": "msedge_proxy.exe"
  }
]
```

## How it works

- Stager: the download host, path and user agent are UTF-16 literals passed to WinHTTP; the port is the immediate loaded into `r8d` before `WinHttpConnect`. The decryption loop is found by its bytes (`mov edx, seed; xor [rbp+rax], dl; shl ecx, n; sub ecx, edx; lea edx, [rcx+rax]`), which gives `out[i] = in[i] ^ (k & 0xff)`, `k0 = seed`, `k = k * (2^n - 1) + i` (seed `0xFFFFFFA7`, low byte `0xA7`, multiplier 31 in the known build).
- Container: after decryption, `u32 decoy_len | decoy | u32 name_len | name | RAT`. The stager writes a non-empty decoy to `%TEMP%\<name>` and opens it, then writes the rest to `%TEMP%\msedge_proxy.exe` and starts it hidden. The 52,744-byte `payload.bin` in Point Wild's report is 8 bytes longer than the 52,736-byte RAT, which fits a header with two zero lengths (no decoy).
- RAT: the tool walks the IL of every method, pairing `ldstr` (and `String.Concat` with `Environment.UserName`) with the static field that `stsfld` writes. It reports which `AppConfig` fields are written but never read, whether `EnvironmentCheck.Enabled` is ever written (it isn't, so the anti-VM checks never run), the command strings from the dispatcher and the CLR header's 32-bit flag.

## Tested on

| SHA-256 | File | Result |
|---|---|---|
| `8f39fe882e45dfa8a7446d59dfef86b583a868ff846ade86124a57041f5c63fd` | stager (`WindowsUpdate.exe`) | URL, seed 0xA7, multiplier 31, `msedge_proxy.exe` |
| `0d41ce75da4f3404734358411a72ffc4169376dcfebda52ac50eb66eac73d2f6` | RAT (`msedge_proxy.exe`) | config, certificate, 18 commands, 11 floods |

The real `payload.bin` is not public. `--payload` was tested on two containers built from the RAT with the stager's own keystream: one with an empty header (52,744 bytes, the size Point Wild reported) and one with a decoy file. Both returned the RAT's SHA-256.

## Credits

Point Wild Lat61 (Prathamesh Shingare, Kedar Shashikant Pandit): [BotHelper RAT: From Encrypted Payload to Live Screen Surveillance](https://www.pointwild.com/threat-intelligence/bothelper-rat-from-encrypted-payload-to-live-screen-surveillance/).
