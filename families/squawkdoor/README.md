# SquawkDoor (SquadC)

Extracts the configuration of SquawkDoor, the backdoor Check Point calls SquadC: C2 address, magic tag, check-in URL, beacon interval and, in newer builds, the browser-wait and anti-analysis flags. It accepts the certificate-fix MSI installers directly, the encrypted payload file dropped next to the sideloading host (`hhc`), a decrypted stage 2, or a carved image. It only parses files; nothing is executed.

Write-up: [SquadC is SquawkDoor, and one of its installers is SparrowDoor](https://stateless-re.github.io/2026/squadc-is-squawkdoor/)

## Usage

```sh
pip install pefile olefile
python extract.py INSTALLER.msi [hhc ...] [-o OUTDIR] [--key KEY]
```

`-o` writes each restored backdoor image to `OUTDIR/<sha256>.bin` (mode 600). `--key` overrides the RC4 key `Hg5th5324Ve`.

Output for the Indonesian installer (copied from a run):

```json
[
  {
    "file": "orig/e9f2f42ea3611096879f4152a7d78bb3a78a4dbead1c3b7e366dce485207551f.msi",
    "sha256": "e9f2f42ea3611096879f4152a7d78bb3a78a4dbead1c3b7e366dce485207551f",
    "configs": [
      {
        "source": "File_1_hhc",
        "image_sha256": "98c919734910cc7a825f9b5b4f7390831ba32cf054a01b5b7bf5e37a352f9155",
        "image_timestamp": "2026-05-14 06:09:07",
        "config_version": "v2",
        "config_size": 396,
        "c2": "135.136.135.54:443",
        "magic_tag": "XlocmwW",
        "ping_url": "https://pplpp.microsfot.vip/register-ip",
        "beacon_interval_minutes": 10,
        "need_browser_waiting": 0,
        "anti_analysis_enabled": 1
      }
    ],
    "error": null
  }
]
```

A file without a SquawkDoor payload gets `"error": "no SquawkDoor payload found (wrong key or not SquawkDoor)"` and the exit status is 1. That is what happens with `e5f7bbfc…`, an installer from the same campaign that carries SparrowDoor.

## How it works

For an MSI, the tool opens the compound file with `olefile`, finds the stream that starts with `MSCF`, and unpacks the cabinet itself (MSZIP blocks are raw deflate with the previous block as dictionary, which `zlib` handles). For each file it checks whether RC4 with the key turns the first nine bytes into `55 8B EC 64 A1 30 00 00 00`, the start of the stage 2 stub. The backdoor image sits at offset `0x400` of stage 2 with `MZ` and `PE\0\0` zeroed; the tool writes them back and trims the image at the end of its last section. The config is RC4-encrypted at the start of `.data`. Its length comes from the copy loop that loads it, `mov ecx, N` followed by `mov esi, <.data>`: N = 0x61 dwords (388 bytes, v1, no flags) or 0x63 dwords (396 bytes, v2). RC4 is implemented in the file because `cryptography`'s ARC4 rejects the 88-bit key.

## Existing tools checked (November 2026)

No public extractor or YARA rule for SquawkDoor or SquadC turned up: GitHub code search for `SquawkDoor`, `squadc_single_instance`, `Hg5th5324Ve` and `XlocmwW`, CAPE's parsers, and the two vendor reports (neither publishes code or rules).

## Tested on

The three SquawkDoor installers from Check Point's and Positive Technologies' reports, their payload files, and the restored images. Each gives one config; `b379d07b…` is v1, the other two are v2.

```
b379d07ba81d4190490d9893b2d6d830ff594e042dce26053ef07794d0403787  MSI, v1, 103.141.235.123:443
e9f2f42ea3611096879f4152a7d78bb3a78a4dbead1c3b7e366dce485207551f  MSI, v2, 135.136.135.54:443
f51dc5e1848daee4e607d46faa25033e1151060cd3482ad4439754440d6c4c01  MSI, v2, 135.136.135.54:443
1c28aaa57223794ad34b0ebc063dc450187425e5c9b38a2c32276d8ea34c9f27  hhc, v1
83bc97e0a7da7030cac699a239b7071e84a388bc235a0cd9d3d01a5639915f08  hhc, v2
9120968808b262f030c1dbb37cafa0706d7d110e957655676396e0d5299953ac  image, v1
98c919734910cc7a825f9b5b4f7390831ba32cf054a01b5b7bf5e37a352f9155  image, v2
```

Rejected as expected: `e5f7bbfc187264336dea5dfebfb5a7dd1e7fcdcc9692db55fbe6eb4d28f027bc` (SparrowDoor installer) and the loader DLLs, which contain no config.

## Credit

Positive Technologies [described SquawkDoor first](https://positechglobal.com/en/research/pt-esc-threat-intelligence/famoussparrow-attacks-with-updated-sparrowdoor-backdoor-and-new-squawkdoor-backdoor/), including the RC4 key and the v2 config structure. Check Point Research reported it as SquadC in its [CopperDragon report](https://research.checkpoint.com/2026/not-all-that-glitters-is-gold-tracking-copperdragons-sparrow-framework-around-the-globe/), with the hashes this tool was tested on.
