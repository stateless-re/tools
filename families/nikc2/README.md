# NIK C2 (NIKRAT) config extractor

Extracts the configuration of NIK C2 agents (the Go RAT Talos calls NIK C2 and MalwareBazaar labels NIKRAT): primary C2, user ID, seed and the AES-256-GCM key derived from it, agent ID, certificate pin, feature flags, server list and fallback. It also unwraps the two delivery wrappers seen so far, the FileCrypt `FCX1`/`SX11` packer and a PyInstaller binder, in memory.

Write-up: [Twenty NIK C2 files, one panel account, and a build that can't read its own config](https://stateless-re.github.io/2026/nik-c2-config/)

## Usage

```sh
python extract.py SAMPLE [SAMPLE ...]
python extract.py --no-handlers SAMPLE
python extract.py -o OUTDIR PACKED_OR_BINDER
```

Output is JSON on stdout. `-o` writes unwrapped inner files, named by SHA-256, mode 600. Exit status is 1 if any input has no agent config.

## Example

The FileCrypt-packed file `9d9d9901…` (flags list abridged, URLs defanged):

```json
{
  "file": "9d9d9901b318cf30a8764f8b1a4d042e9c73bc22cfd39e159f81ba895a898920.exe",
  "wrappers": [
    {
      "type": "FileCrypt FCX1/SX11",
      "offset": "0xde00",
      "inner_name": "client (15).exe",
      "inner_sha256": "876b1dbc4bcfc548d1fbf8ac8d4fe7dfa15df80e5085372397dffb814c5e5352"
    }
  ],
  "agents": [
    {
      "sha256": "876b1dbc4bcfc548d1fbf8ac8d4fe7dfa15df80e5085372397dffb814c5e5352",
      "format": "v1",
      "xor_key": "4e494b",
      "config": {
        "c2": "hxxps://191.44.109[.]125:443",
        "user_uid": "7b85683a-c3e6-43c2-9bfb-583377ada5f6",
        "seed": "496d1180e03e10287938140d0011f21c006b003d6a904e08c41564566f204af9",
        "agent_id": "ag_d83fbbc293c0",
        "process_name": "svchost.exe",
        "cert_pin_sha256": "750872a67ceb2adbe1e31340acabc6574aa9ebbcfe8acaad9ffe05301eca21dc",
        "cert_pin_slot": "0xc0",
        "aes_key": "cba0604726a6aa8c0f56cad2fafeb36d70f4ee38baaf75069f60895a61dc0b46",
        "flags": {
          "hide_console": true,
          "watchdog": true,
          "masquerade": true
        }
      },
      "server_lists": [
        {
          "global": "0x140720b70",
          "encoded_length": 0,
          "servers": []
        }
      ],
      "fallback_urls": [
        "hxxps://2.26.51[.]12:443"
      ],
      "symbols": false
    }
  ],
  "error": null
}
```

## How it works

The agent keeps its config in a block of 16-byte Go string headers in `.data`. Four slots (primary C2 at +0x00, user ID +0x10, seed +0x30, agent ID +0x40) are hex strings decoded with `out[i] = in[i] ^ ((key[i % 3] + i) & 0xff)`, where `key` is `NIK` in every build seen; the tool derives the key from the known plaintext `https://` rather than assuming it. The rest of the block is plain: `true`/`false` flags, the masquerade file name and the certificate pin, which is SHA-256 of the C2 server's DER certificate. The AES key is SHA-256 of the seed's ASCII text. The decoder function is found by its in-place call pattern (`mov rax,[g]; mov rbx,[g+8]; call dec; mov [g+8],rbx`) and the server-list global is the other `dec` call that doesn't write back, so symbol-stripped builds work too. Handler names are read from the Go function table when it is present.

Builds in the v2 format store fields as Base64 `wrapped_key|iv|ciphertext` or `iv:ciphertext`; the tool reports their shape only. In the one v2 build seen, the agent itself can't decrypt them (it passes the 256-byte wrapped key straight to `aes.NewCipher`), and falls back to defaults.

FileCrypt: the last 8 bytes are `<u32 length> "FCX1"`; the blob is `"SX11" | salt(16) | gcm_nonce(12) | chacha_nonce(12) | u32 length | ChaCha20-Poly1305(AES-256-GCM(payload))`, both with AAD `"SX11" | salt` and keys from HKDF-SHA256 over a master key embedded in the packer. The payload is `flag | u32 name length | name | u32 data length | data`, gzip when flag is 1.

## Tested on

All twenty files in the write-up (18 agents, 1 PyInstaller binder, 1 FileCrypt-packed file); every one returns a config:

| SHA-256 | Format | Primary C2 | Result |
|---|---|---|---|
| `0008c95fb43bd97dec04c408b61a66a38f59a7912e4d4a058647ef14407463f2` | v1 | https://191.44.109[.]125:443 | ok |
| `0fb93dbb9525004f9e5b1ee4bcd6b6638700bee576413e955c8c96292fa964ee` | v1 | https://2.26.51[.]12:443 | ok |
| `1fee4cd8d3560e6c60ba50451860adf6e705f26fd3fe1c1ccc058f4e8b13073a` | v1 | https://total-sitevv[.]lol:443 | ok |
| `2a01056369cc691f5bed6bd2654930a81d1bc240a568a0d5b209aceef3b5c9c9` | v1 | https://total-sitevv[.]lol:443 | ok |
| `30817712277bba54e4cb8640f4005aad35f5172f88cf046aea545d029e12ccba` | v1 | https://total-sitevv[.]lol:443 | ok |
| `46bea5c1ac50bbcb0fb700e6e8f46d5f09c8ea61c74f677bd19342bace670052` | v1 (inner `e7f51534b110`) | https://2.26.49[.]181:443 | ok |
| `507436d5132cefeea7e35e3481c5726f00a90e041a6bbb55cfcf50b51e2b3b73` | v1 | https://2.26.49[.]181:443 | ok |
| `5a39bd95d430a1093b3d179d100389ee2cf60226518b82e02572f3e25df2f803` | v2 | protected (v2) | ok |
| `5d25efba2119f52d08214a590fedb45a5c9fe5e2850fd87e7bca24c92745e6d1` | v1 | https://total-sitevv[.]lol:443 | ok |
| `626619e1a2ba0cfaf7809ad3fed0d8958762379bcdc549125699ce7e6a938500` | v1 | https://2.26.49[.]181:443 | ok |
| `6583eb22ca554e749b647d68ae76f7279a8dc538196ebde1412669357a027de5` | v1 | https://total-sitevv[.]lol:443 | ok |
| `876b1dbc4bcfc548d1fbf8ac8d4fe7dfa15df80e5085372397dffb814c5e5352` | v1 | https://191.44.109[.]125:443 | ok |
| `99573a79f393299049216237d0d23761d67f6a8507a7a0cfe17cb30837f68f00` | v1 | https://total-sitevv[.]lol:443 | ok |
| `9b228bf578fee16d5ccd880ecafcc7159d3678ef09d7fa5c807d423f97d48a9e` | v1 | https://2.26.49[.]181:443 | ok |
| `9d9d9901b318cf30a8764f8b1a4d042e9c73bc22cfd39e159f81ba895a898920` | v1 (inner `876b1dbc4bcf`) | https://191.44.109[.]125:443 | ok |
| `a7279f2425746deafef5c2ff6ebe612c7cc6062601be37d83e07ecdd1bb72ba2` | v1 | https://87.120.196[.]120:443 | ok |
| `ae38f1181c9dd0db7224d6023e335eb2cdabb0f441906d14ffba8602b7abca3c` | v1 | https://total-sitevv[.]lol:443 | ok |
| `bf83345ca66bdc4bd45ade608a06361d18927dd80351e9a1d8cbe8eda5d78402` | v1 | https://total-sitevv[.]lol:443 | ok |
| `d0abbd4e13d026cea0f62d250080f721a37c3a033afb6b5ec368b31e07243f24` | v1 | https://total-sitevv[.]lol:443 | ok |
| `e7f51534b1106707a7e86b1531dfd4444639b824baec66c5e1ad8005b1f7da0a` | v1 | https://2.26.49[.]181:443 | ok |

## Credit

Cisco Talos (Chetan Raghuprasad), [NIK C2: The new AI-enabled command-and-control framework](https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/), published a seed and key that this tool reproduces. Threatray published [NIKRAT IOCs](https://github.com/threatray/threat-research/tree/main/2026-10-30-NIKRAT) and uploaded twelve of the samples to MalwareBazaar.
