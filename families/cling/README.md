# Cling / ClingSTUN

Reads Cling (ClingSTUN, UFlowBot) Linux ELF builds and prints the STUN server list, the `selfrep` propagation tags, the exploit targets (method and path only) and persistence or hiding markers as JSON. For builds whose strings are ChaCha20-encrypted, it finds the key and nonce in the data sections and decrypts `.rodata` without a disassembler.

## Usage

```sh
python3 extract.py FILE [FILE ...] [--strings]
```

`--strings` adds every recovered string to the record. Exit status is 1 if any file fails; that record gets an `error` field. Requires `pyelftools` and `cryptography`.

## Example (abridged)

```json
[
  {
    "file": "cling_nozomi/3a6927a3399f2a10bb2e2229482e5096e5f1c3401a87f7f1730db11243531e28",
    "sha256": "3a6927a3399f2a10bb2e2229482e5096e5f1c3401a87f7f1730db11243531e28",
    "machine": "EM_MIPS",
    "class": 32,
    "endian": "little",
    "string_encryption": {
      "algorithm": "ChaCha20, counter 0, keystream restarts at every string",
      "key": "161e191b111f001d041c0e080b1a120705090d0f060a15010c141f1702031318",
      "nonce": "1e004a000000000000000000",
      "strings_decrypted": 62
    },
    "stun_servers": [
      "74.125.250.129",
      "216.93.246.18",
      "81.187.30.115",
      "..."
    ],
    "stun_server_count": 13,
    "uses_8_8_8_8": true,
    "selfrep_tags": [
      "realtek.selfrep",
      "selfrep.jaws",
      "selfrep.router",
      "selfrep.tbk"
    ],
    "exploit_targets": [
      "GET /cgi-bin/shortcut_telnet.cgi",
      "GET /device.rsp",
      "GET /shell",
      "UDP orf; (Realtek UDPServer)"
    ],
    "markers": [
      "oom_score_adj",
      "persistence_copy",
      "proc_bind_mount",
      "tmp_cleanup",
      "watchdog",
      "wget_hijack_wrapper"
    ]
  }
]
```

## How the string decryption works

In 3a6927a3 every string is encrypted on its own with ChaCha20, counter 0, so each one starts at the beginning of the same keystream; the NUL terminator and padding are left in clear. The 12-byte nonce sits at the start of `.data` and the 32-byte key right after it (in 3a6927a3 the key is the byte values 0x00 to 0x1f shuffled, with 0x1f twice and no 0x10). The tool tries every 4-byte-aligned nonce+key pair in `.data`, `.data.rel.ro` and `.rodata`, keeps the one that turns the most `.rodata` entries into dotted-quad IPs, then walks `.rodata`: a string runs while the decryption stays printable and ends at a zero byte that is followed by padding or by another valid string. Strings shorter than 4 characters (`.p`, `.r` in 3a6927a3) are skipped. One call site in 3a6927a3 passes the wrong address (0x413068, one byte before the ciphertext of `/tmp/statm`); the tool reports the string where it really starts. Plaintext builds are read directly.

STUN servers are listed in file order, which in the encrypted build is not the order the bot uses them.

## Tested on

| SHA-256 | Result |
|---|---|
| `3a6927a3399f2a10bb2e2229482e5096e5f1c3401a87f7f1730db11243531e28` | MIPS, ChaCha20, 13 STUN servers, 4 exploit targets |
| `90d738a8d650e3fefda9d7efa4baa11bd89ab05fcf0eb173e04aa01a52b465e2` | MIPS, 13 STUN servers, 8 exploit targets |
| `10d83c1748895361e07320f68d44d427b43cadd2cbffe0ab5e607ab03aec83da` | MIPS, 24 STUN servers, 0 exploit targets |
| `121f2050e3c891b29565fd73451fff7ae60199c86eb8d79ec1eb1d9844578487` | ARM, 13 STUN servers, 7 exploit targets |
| `284e5ec8748f99fd1b8c331b699a5fe5fd4448bbaae0347a940f427f931c4d14` | 386, 24 STUN servers, 0 exploit targets |
| `2ed54e0f988a62039abed88f6394eb1e3d5ed931f0183556055417fb08844ecf` | MIPS, 24 STUN servers, 0 exploit targets |
| `48962b3893f2c8261e32e6b95ea7d463d145a529a8b2a6c987dd979454405c73` | MIPS, 13 STUN servers, 7 exploit targets |
| `48f9b72ce72ab7087794650d6eef10135345088384fbde1482f1c74a02b80302` | ARM, 13 STUN servers, 7 exploit targets |
| `4fbd61cb9181ebbc4fe9a6e59d3c346dc00001da48d66bd890556fc6fad22b07` | ARM, 13 STUN servers, 7 exploit targets |
| `6581bf37184bb2db899b9893064d39dd314ea691adf3281cc0aa7e0a31e5138a` | 386, 24 STUN servers, 0 exploit targets |
| `76692a23abe718b93e63edefd743971ec627c0cdf3778f856bd5ec88003deaa2` | MIPS, 13 STUN servers, 7 exploit targets |
| `9391c6ad17aced1142607c0c623b18d86a7697cc483d204ffac94093e26b8068` | ARM, 24 STUN servers, 0 exploit targets |
| `a297eddfa7abea8d411afc0f150f8f6f30e470a77204de87e3b0815fa9bb8a84` | AARCH64, 13 STUN servers, 7 exploit targets |
| `b90640b392827b4f2d280f6cf67860862953331917d42df23e1653a92f2f98ad` | PPC, 24 STUN servers, 0 exploit targets |
| `c0d8ffebfba969b1c1ca76bd9623bb623e9f95155c8ceca77d8fcc521435a497` | ARM, 24 STUN servers, 0 exploit targets |
| `c1d8e2829ea63b9dc1cf2c3421a5093406adad4d6622e238376e78e908e0e6e8` | 386, 13 STUN servers, 7 exploit targets |
| `dfba6008a2c828a9cb62342aec53006ae05a60cb8d4c41c3fa216fd727e8c6a3` | X86_64, 24 STUN servers, 0 exploit targets |
| `e4d12208789f36efc5a1ff765088fed95d6bb5972d1a804a4536fd42366797d4` | 386, 24 STUN servers, 0 exploit targets |
| `e6e113783356446aef66e5296db45b244f318292af7cebc2a9bd76f095a95c4c` | 386, 13 STUN servers, 7 exploit targets |
| `ec199c78c11040fd3127887222fd75a85e5797bf96aa691a117fdd83dd663d81` | X86_64, 13 STUN servers, 7 exploit targets |
| `f49f45303cbfccee14ff193ac9608f860e6d616f08c0ecbef1ec44f7c863d7ec` | ARM, 24 STUN servers, 0 exploit targets |

The two `wget.sh` droppers in the same report (5c4e2635..., dc892f50...) are shell scripts and are rejected with an error.

## Credit

eFeSpain's [Cling chapters](https://blog.efespain.com/cling/), Nozomi Networks Labs' [A STUNning Disguise](https://www.nozominetworks.com/blog/a-stunning-disguise-cling-malware-masquerades-as-google-) and Fortinet's [ClingSTUN report](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure). Write-up: [ClingSTUN's scanner checksums 20 bytes of every SYN and sends 256](https://stateless-re.github.io/2026/clingstun-syn-checksum/).
