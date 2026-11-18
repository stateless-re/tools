# SteamHide

Static tool for SteamHide, the 2021 .NET downloader and backdoor that G Data reported hiding an encrypted executable in a Steam profile image's ICC profile (GDI+ property `0x8773`, `PropertyTagICCProfile`). Given a downloader or backdoor it prints the password, salt, Steam profile URL, image regex and Pastebin URLs; given an image it pulls out the ICC data and decrypts the payload.

Write-up: [SteamHide's newer samples are the old ones after a pass through LIEF](https://stateless-re.github.io/2026/steamhide-lief-copies/)

## Usage

```sh
python extract.py downloader.exe backdoor.exe
python extract.py carrier.jpg -o outdir
python extract.py --raw icc_blob.bin -o outdir
python extract.py carrier.jpg --password '...' --salt 22410b0c100041805c484117570b0a08 --iterations 192
```

A file starting with `MZ` is parsed as a SteamHide PE (strings from the `#US` heap, salt from the `FieldRVA` initializer). Anything else is treated as an image: JPEG APP2 `ICC_PROFILE` segments (concatenated in sequence order), JPEG EXIF tag `0x8773`, PNG `iCCP`, TIFF tag `0x8773`, or with `--raw` the bare blob. `-o` writes a decrypted payload named by SHA-256, mode 600. Nothing is loaded or run. Exit status is 1 if any input fails, including an ICC profile that doesn't decrypt to a PE.

Requires `dnfile` and `cryptography`.

## Output (abridged)

```json
{"sha256": "148914b6c64c51130a42159e4100e6eb670852901418d88c1c0383bf0cd1e339", "kind": "pe", "password": "{PjlD\\bzxS#;8@\\x.3JT&<4^MsTqE0", "password_hex": "7b506a6c445c627a7853233b38405c782e334a54263c345e4d7354714530", "salt_candidates": ["22410b0c100041805c484117570b0a08"], "profiles": ["https://steamcommunity.com/id/advance40/images"], "image_pattern": "<img style=\"width: 100%;\" src=\"(https://steamuserimages-a.akamaihd.net/ugc/\\d+/.*?/)?", "pastebin": []}
{"sha256": "b41868a6a32a7e1167f4e76e2f3cf565b6c0875924f9d809d889eae9cb56a6ae", "kind": "pe", "profiles": ["https://steamcommunity.com/id/"], "pastebin": ["https://pastebin.com/raw/", "https://pastebin.com/raw/xLTeenQV"], "names": ["BroMal", "uNoFGmsEX", ".txt", "final.exe", "SquirrelSetup.log"]}
{"sha256": "f3144488cf7aec820908d391d4a492718c77b499c1db06af59a367fc22ff50b2", "kind": "image", "icc_source": "jpeg-app2-icc", "icc_size": 23560, "icc_looks_genuine": false, "decrypted_size": 23552, "decrypted_sha256": "b41868a6a32a7e1167f4e76e2f3cf565b6c0875924f9d809d889eae9cb56a6ae", "decrypted_is_pe": true}
{"sha256": "0343d6fe660e2f91ed028f83dc4ad27d255808fae34cb4ec44ae5d531fe8d635", "kind": "image", "icc_source": "jpeg-app2-icc", "icc_size": 3048, "icc_looks_genuine": true, "decrypted_is_pe": false, "error": "ICC data does not decrypt to a PE with this key"}
```

## How it works

The samples derive the 3DES key with .NET's `PasswordDeriveBytes(password, salt, "SHA512", 192)` and call `GetBytes(24)` then `GetBytes(8)`. Because 32 bytes fit in one SHA-512 output, that reduces to: `h = SHA512(utf8(password) || salt)`, then 190 more rounds of `h = SHA512(h)`, then `block = SHA512(h)`; key is `block[0:24]`, IV is `block[24:32]`, mode CBC with PKCS#7 padding. The password has single backslashes (`{PjlD\bzxS#;8@\x.3JT&<4^MsTqE0`, 30 characters); the doubled form printed in G Data's report derives a different key. The derivation was checked against .NET 8's own `PasswordDeriveBytes` and `TripleDES` (same key `5AD3B743A474B24211B3809D07D6B517365F6161BF8A975B`, IV `5F49826133F6F7A2`; a .NET-encrypted copy of the backdoor decrypts to the original bytes).

## Tested on

| SHA-256 | file | result |
|---|---|---|
| 148914b6c64c51130a42159e4100e6eb670852901418d88c1c0383bf0cd1e339 | downloader | password, salt, profile, regex |
| 368c97aef6c41b83d06c0ebb1f52679ff96a9aea35499a1caa8c3115cd16880b | downloader (LIEF-rebuilt copy) | same as above |
| b41868a6a32a7e1167f4e76e2f3cf565b6c0875924f9d809d889eae9cb56a6ae | backdoor | password, salt, profile base, Pastebin URLs, names |
| 194c18dc8bc923887ff6b6f2acacd00b54890ca1c52233581c7802fd176dc056 | backdoor (LIEF-rebuilt copy) | same as above |
| 0343d6fe660e2f91ed028f83dc4ad27d255808fae34cb4ec44ae5d531fe8d635 | JPEG still on the Steam profile (2017) | genuine ICC profile, does not decrypt (exit 1) |

No 2021 carrier image is publicly available, so the image path was tested on carriers built from .NET-encrypted ciphertext: a JPEG with the blob in an APP2 `ICC_PROFILE` segment, a JPEG with it in EXIF tag `0x8773`, and the bare blob. All three decrypt to `b41868a6...a6ae`.

## Credits

Karsten Hahn, G Data: [Picture this: Malware Hides in Steam Profile Images](https://blog.gdatasoftware.com/2021/06/36861-malware-hides-in-steam-profile-images) (2021). TheAbsnt: [SteamHide Malware Analysis, part I](https://theabsnt.github.io/malware-analysis/steamhide-analysis/part01) and [part II](https://theabsnt.github.io/malware-analysis/steamhide-analysis/part02) (2024).
