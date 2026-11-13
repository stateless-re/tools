# 2CLoader

Extracts the 0xDC-byte config from a 2CLoader executable, derives the AES-256 key from the hash of the loader's own code section, removes the two XOR layers, decrypts the payload with AES-GCM and decompresses it (Xpress Huffman). Nothing is executed.

Write-up: [2CLoader keys its payload to its own padding](https://stateless-re.github.io/2026/2cloader-keys-its-payload-to-its-own-padding/)

## Usage

```sh
pip install pefile cryptography dissect.util
python extract.py SAMPLE.exe [MORE.exe ...]               # config, key and payload hash as JSON
python extract.py SAMPLE.exe -o payloads/                 # also write the decrypted payloads
```

Output, abridged:

```json
{
  "sha256": "0017821181723261801e24abb9d33c739f382889d46dbf46d320c87ac62e5ca6",
  "resource": "88/521/0",
  "config": {
    "payload_name": "build_tbuild.exe",
    "build_time_utc": "2026-08-30T11:51:25+00:00",
    "injection_target": "dllhost.exe",
    "persistence_flags": "0x3f",
    "task_interval_hours": 7
  },
  "key_source": "code section, virtual size",
  "payload_sha256": "ad9d1679fb2f90477fe8e81a4be51566b84f154eb3f2b7200a7b0faca0715636",
  "payload_size": 1357312
}
```

The exit status is 1 if any file fails; its JSON record then has an `error` field.

## How the key is found

The key is `SHA-256(code section) XOR (key_mask_low || key_mask_high)`, checked against the config's byte sum. The loader hashes the section as mapped in memory, which is its virtual size; the raw size is tried as a fallback.

## Tested on

All twelve samples from the Zscaler ThreatLabz report that were on MalwareBazaar in November 2026, covering both stub versions. Every payload decrypts and passes the AES-GCM tag check.

```
0017821181723261801e24abb9d33c739f382889d46dbf46d320c87ac62e5ca6
06185d74edbdc06f99095e96f74aa2e49a1cda2d02a294c11a9ac35a0231075e
066d83b98a2081e0bb075c94376aebc9b0fd6499025cab1762d83bbb4d7576c6
0a2ef2c360cf6e3e3e5d844ca03fecc31924ba0e8c3ecd8aefa778cae10fb19e
0d2abd7d872196abd951f1d7ed6406486499e5d5acc04f28fcd4f45b1851711e
1337ed6fe9c6205b569670a40eab42b51ba69c5c1724d61474e8595acd90ecfb
246717653bc2ae2e09036bac56c9d79940c652972a73f4c6aa9b925c28cce095
2c786f7009cc5e1fba5471a88b23b34dce6e1578ee9f664ec62bf48227ba384b
2d43d592630ad1e012da63ef7279f95dd4a8e94964e12ca2f996051875574fa6
30cf47caf9700a74a8ea4a728b8b7c88cb1f8e22261b4ac01575b112c1e224ca
3286ff477ccd888479b96d0ffb2bd53962862db7267a4bd1c8d8f8c22fec63d4
4c16f5ebd5c633b7a793ffa2cd96daddc5a503d82ed4fbe636109d89164ec02b
```

## Credit

The config layout and decryption steps were first published by Muhammed Irfan V A at [Zscaler ThreatLabz](https://www.zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus). Decompression uses [dissect.util](https://github.com/fox-it/dissect.util).
