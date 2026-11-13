# Remus

Extracts the C2 configuration from x64 Remus stealer payloads: the three ChaCha20-encrypted C2 URLs, the Ethereum fallback (RPC endpoint, contract address and function selector) and the build tag. It only parses the file; nothing is executed.

Write-up: [What 2CLoader delivered: Vidar on Epic Games profiles, Remus on Ethereum](https://stateless-re.github.io/2026/what-2cloader-delivered/)

## Usage

```sh
pip install pefile cryptography
python extract.py PAYLOAD.exe [MORE.exe ...]
```

Output for one payload (copied from a run):

```json
{
  "file": "4c16f5eb.payload",
  "sha256": "4713985869f284136d2d9f9c98a1cd43c2f327a7619d829e31fc69c3589f56cb",
  "chacha20_key": "9a8af2a33aa8726ac458a49bf8b3cde41c576c3b9dbdec2bcb8796539abaae9e",
  "chacha20_nonce": "1e9f136d422ab08b",
  "c2": [
    "http://fresok.top:9048/messages",
    "http://shhsift.click:7647/messages",
    "http://vexdico.shop:8539/invoices"
  ],
  "rpc_endpoints": [
    "https://ethereum-rpc.publicnode.com"
  ],
  "eth_contract": "0x999941b74F6bbc921D5174A5b29911562cd2D7CF",
  "eth_selector": "0xc2fb26a6",
  "tag": "03473d3f2d528ba787191417a6e1e5f0",
  "error": null
}
```

The exit status is 1 if any file fails; its record then has an `error` field (for example `ChaCha20 C2 slots not found` on a file that isn't Remus).

## How it works

The C2 key setup is called with `lea rdx, key` and `lea r8, nonce`, and the nonce sits 0x20 bytes after the key in `.rdata`. The tool finds that pair of instructions, reads the 32-byte key and 8-byte nonce, and decrypts the 64-byte slots that start 0x10 bytes after the nonce. The cipher is original ChaCha20 (8-byte nonce, 64-bit block counter). The sample keeps one cipher state for all slots, so slot *n* is decrypted with block counter *n*. Other strings, including the `eth_call` JSON body and the RPC URL, are stored as `c[i] ^ ((i + 1) * k)` with a per-string constant `k`, in bytes or 16-bit units. The tool recovers `k` from a known plaintext prefix (`{"jsonrpc"`, `https://`), so it needs no per-build constants. The build tag is the string that the pointer at `.data+0x10` refers to. The sample uses the same string as the `tag=` value and as the name of the object `\BaseNamedObjects\<tag>` (other reports call it a mutex; the creating syscall's arguments fit `NtCreateEvent`).

## Existing tools checked (November 2026)

None of these extract the config from these payloads statically:

- CAPE `cape_parsers/CAPE/core/Remus.py` parses a config that the sandbox dumps at run time and returns nothing for a PE file.
- CAPE `cape_parsers/CAPE/community/Lumma.py`: none of its four YARA locators match these payloads (it targets 32-bit Lumma).
- [ZPetricusic/LummaExtractor](https://github.com/ZPetricusic/LummaExtractor): its key and build-ID byte patterns are absent from all four payloads.
- [tan2pow16/Lumma-C2-Extractor](https://github.com/tan2pow16/Lumma-C2-Extractor) rejects any file that isn't a 32-bit PE.
- [01Xyris/LummaC2-Extractor](https://github.com/01Xyris/LummaC2-Extractor) describes itself as dynamic extraction.

## Tested on

The four Remus payloads unpacked from the 2CLoader samples in Zscaler ThreatLabz's report. All four give three C2 URLs, the Ethereum fallback and the tag.

```
d488a4b0e6837264517b81596ce5d6fbbc61d3ef68d938c0e0d7b9a9a1915f26
8696940855d849d5d6aa1a52896855082bde0fa76da23cdaeca028a5493d4fb1
4713985869f284136d2d9f9c98a1cd43c2f327a7619d829e31fc69c3589f56cb
6f3e8965f7cb3d800ca06482ebf3800f6873ab88078d8735c416aa25b81179d6
```

## Credit

Vojtěch Krejsa and Jan Rubín at [Gen Digital](https://www.gendigital.com/blog/insights/research/remus-64bit-variant-of-lumma-stealer) first described Remus, its ChaCha20 config in `.rdata` and its use of Ethereum. [Malware Cake Factory](https://malwarecakefactory.github.io/malware-analysis/remus-protected-startup-tasking-analysis/) documented the endpoint slots, the selector and the `tag`/`exp` registration fields on the payload `4713985869f2…`. The contract and the selector also appear in Malware Cake Factory's [earlier post](https://malwarecakefactory.github.io/malware-analysis/remus-c2-protocol-analysis/).
