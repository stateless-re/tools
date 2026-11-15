# Fake Steam client kit

Static triage for a Steam phishing kit that writes a fake `steam.exe` over the real one: the .NET launcher `HiddenAutoLauncher`, the native loader, the .NET and native fake clients, and the `SteamInstall.exe` restorer. For each file it prints the phishing URLs stored as plain strings, the WebView2 command-line switches, whether the `steamcommunity.com` restore trigger, `steam.back` and the `window.steamm` bridge methods are present, and every embedded PE it can find, with the XOR key and interleave block size used to hide it.

Write-up: [A fake steam.exe used to put the real one back. Its September build lets the phishing page read the Steam folder instead](https://stateless-re.github.io/2026/fake-steam-client-bridge/)

## Usage

```sh
python extract.py FILE [FILE ...]
python extract.py LOADER.exe -o outdir
```

`-o` writes every embedded PE to `outdir`, named by its SHA-256, mode 600. Nothing is loaded or run. Exit status is 1 if a file shows none of the kit's traits.

Requires `pefile` and `dnfile`.

## Output (loader `14a0b7d5` and September client `f27af032`, switches abridged)

```json
{
  "file": "14a0b7d57f22378472a4e1d20fc50d38db5dab72d46007b472d466049181ab0b.exe",
  "sha256": "14a0b7d57f22378472a4e1d20fc50d38db5dab72d46007b472d466049181ab0b",
  "kind": "native",
  "phishing_urls": [],
  "webview2_switches": [
    "..."
  ],
  "bridge_methods": [],
  "restore_trigger": false,
  "steam_back": true,
  "embedded_pes": [
    {
      "offset": 547520,
      "size": 1691856,
      "xor_key": "a12b5c7d3e9f4ab8",
      "interleave_block": 0,
      "sha256": "0223fa1e8d5bd5e4344fb8734e60d088e79f262c0a24444d01f240bc996f04e5"
    },
    {
      "offset": 16064,
      "size": 531456,
      "xor_key": "5c18e154351e",
      "interleave_block": 24,
      "sha256": "1d52f76213582b58cd3d0161dee345f42184b05a359607e4719f96c511e7fd3c"
    }
  ]
}
{
  "file": "f27af032b01fc6982ff936086eaeeaa6a517a9b3fad74939ee4e50729c9e3b2c.exe",
  "sha256": "f27af032b01fc6982ff936086eaeeaa6a517a9b3fad74939ee4e50729c9e3b2c",
  "kind": "native",
  "phishing_urls": [
    "https://8909451279.f1shh.at/clie"
  ],
  "webview2_switches": [
    "--ignore-certificate-errors",
    "--allow-running-insecure-content",
    "--disable-web-security",
    "..."
  ],
  "bridge_methods": [
    "win.min",
    "win.close",
    "win.drag",
    "win.resize",
    "http.request",
    "fs.readText",
    "fs.writeText",
    "shell.open"
  ],
  "restore_trigger": false,
  "steam_back": false,
  "embedded_pes": []
}
```

## How it works

.NET files are read with dnfile: user strings for the URL and switches, and managed resources (with or without the 4-byte length prefix of `byte[]` resources) for embedded PEs. For everything else the tool searches for PEs hidden under a repeating XOR key of 1 to 16 bytes, optionally followed by the loader's byte interleave (block sizes 8 to 32, the first half of each block holding the even bytes). It works without knowing the key: a PE built by MSVC or LLD starts with one of two fixed 60-byte DOS headers, and for a key of length L, `stored[i] ^ stored[i+L]` equals `header[i] ^ header[i+L]` because the key cancels out. So the tool XORs the file with itself shifted by L, looks for that pattern with `bytes.find`, recovers the key from the hit, and keeps the hit if the decoded data parses as a PE that fits in the file.

URLs are reported only when stored as a whole string. The native builds from late July on assemble the phishing URL on the stack 16 bytes at a time, so the plain scan sees `https://8909451279.f1shh.at/clie` where the full value is `.../client`. Use FLOSS (`floss --only stack tight`) for those.

## Tested on

| SHA-256 | Role | Result |
|---|---|---|
| `913792a7cec3a062742f3390d7941a7e95aeeb7e1537e4a52590049d54c5c5e8` | HiddenAutoLauncher | resource `svchost.svchost.exe` = loader `14a0b7d5`, plus both of the loader's blobs |
| `14a0b7d57f22378472a4e1d20fc50d38db5dab72d46007b472d466049181ab0b` | loader | WebView2 bootstrapper (XOR `a12b5c7d3e9f4ab8`), client `1d52f762` (XOR `5c18e154351e`, block 24) |
| `a2200e1c82de90bfc23cf8a4ae183b0fb7514b745734aba467ee154e6bc306c1` | .NET client | `7834156259.dojiner.at`, restorer `6594e73e` as a resource |
| `55249a75e9ae5d378fbb24422a200bcfb68d23e4194418647d54ef956b2ffc10` | .NET client | `7834156259.dojiner.at`, restorer `6594e73e` as a resource |
| `7bfd3d6cf9eaebd0766c09c1703c1d0ba4165b9e2125eca70340278115e8dfcf` | native client | `8393546939.dojiner.at`, restorer and WebView2Loader.dll (XOR `deadbeefcafebabe13374269aa55f00d`) |
| `e17fa89521afd0ae54f17b8149a9781baf334f640c061daf270539f609c8a628` | native client | same as above |
| `53ba0183abb4294f0f8cf1c94c06eceac3ef1abfa60e2de16dafca73f783997f` | native client | same as above |
| `bcd91a487e13c62246fdf696a19015795c1ea45a24950a7b9e4b31c5b3f5432d` | native client | same as above |
| `1d52f76213582b58cd3d0161dee345f42184b05a359607e4719f96c511e7fd3c` | native client | no plain URL (stack string); restorer and WebView2Loader.dll, same key |
| `f27af032b01fc6982ff936086eaeeaa6a517a9b3fad74939ee4e50729c9e3b2c` | native client | `8909451279.f1shh.at/clie` (truncated), 8 bridge methods, no restorer |
| `0edcc9061d88c6f0c24ff35d0a2e22387636461db707020d3a70b23cbd523579` | native client | same as above |
| `6594e73edf525c356651e37e5a6876a82c1d0ec554a1062051de5ea8e6101dab` | restorer | `steam.back` found, no embedded PE |

## Credit

The chain, per-build loader keys and the Salat Stealer link were first described by the MalwareBazaar users Daydream and Kejult in their upload comments (2026-10-13), for example on [`1d52f762`](https://bazaar.abuse.ch/sample/1d52f76213582b58cd3d0161dee345f42184b05a359607e4719f96c511e7fd3c/).
