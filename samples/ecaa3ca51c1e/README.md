# FrauPDF installer (ecaa3ca51c1e)

Static extractor for the signed .NET "FrauPDF Setup" installer analyzed in [FrauPDF's installer checks its own file name before it asks for a payload](https://stateless-re.github.io/2026/fraupdf-installer/). It decodes both string layers, rebuilds the four request URLs and lists the embedded files; it can also decrypt a captured payload blob into stage 1 and decode the `uid` query value into the security products it reports.

## Usage

```sh
pip install dnfile cryptography
python extract.py AppPDF_593771.exe
python extract.py AppPDF_593771.exe --names names.txt
python extract.py --blob response.bin -o out/
python extract.py --uid 1a2bcb84
```

`--names` takes one process, service or module name per line and reports which of the installer's hashed tables they match. `--blob` takes the body returned for the download URL and writes the decrypted stage-1 DLL (named by SHA-256, mode 600) when `-o` is given. `--uid` decodes with the download token `1e627e8ceed85007` unless `--token` says otherwise. `--magic` and `--id-add` override the stored-block magic (`0xF112`) and the string ID offset (22) if another build changes them.

## Output (abridged, from the sample, URLs defanged here)

```json
{
 "file": "AppPDF_593771.exe",
 "sha256": "ecaa3ca51c1e9ec0f81a167909999af9f808515e3c35587955e61c228939aeb0",
 "xor_strings": [
  "Installing",
  "Installation complete.",
  "Ready to install.",
  "Applying update...",
  "..."
 ],
 "children": [
  {
   "name": "FrauPDF.Inst.x0pack",
   "size": 1904981,
   "sha256": "de7ccf3e05aa70279da9996d414256f8bdac4a61627d73bf29e82ec26c09f33f",
   "kind": "zip",
   "entries": [
    {
     "name": "fraupdf.exe",
     "size": 3831808,
     "sha256": "117b4f462ca1ca18b206136c63dc03a2a8af07c3c6c0271c3029f9362a524e70"
    }
   ]
  },
  {
   "name": "FrauPDF.Inst.r0bin",
   "size": 27648,
   "sha256": "5d81f494cdf2fab9a9d10384bccdace2899fe73afa58d9be1b156f4930f5b87a",
   "kind": "pe"
  },
  {
   "name": "ILRepack.List",
   "size": 480,
   "sha256": "de2d27bd27a518ac8c6ae509bf2956ee5c3e31b71dd92be9425c192456baba0a"
  }
 ],
 "string_store": {
  "resource": "oNNFP",
  "tag": "lic529D59AB",
  "des_key": "610099aa55b1e0aa",
  "des_iv": "02b4b9b9b8d26bac",
  "header_xor": "15ef6331"
 },
 "resource_strings": [
  {
   "offset": 2937,
   "value": "664dc44ca345a5c2",
   "id": 23594
  },
  {
   "offset": 3037,
   "value": "&p5el=b0663",
   "id": 23638
  },
  {
   "offset": 3058,
   "value": "thepdfsoftsetup[.]com",
   "id": 23469
  },
  "..."
 ],
 "urls": [
  {
   "token": "664dc44ca345a5c2",
   "url": "hxxps://thepdfsoftsetup[.]com/?ver=664d&chan=c44&lang=ca3&arch=45a&build=5c2&p5el=b0663"
  },
  {
   "token": "c0a188a0367d1958",
   "url": "hxxps://thepdfsoftsetup[.]com/?ver=c0a1&chan=88a&lang=036&arch=7d1&build=958&p5el=b0663"
  },
  "..."
 ]
}
```

`--uid 1a2bcb84` (a value encoded by hand from the IL for Defender plus Avast) prints:

```json
{"uid": "1a2bcb84", "mask_weight": "0120", "bits": [7, 10], "products": ["Microsoft Defender", "Avast, AVG"]}
```

## How it works

The installer keeps most strings in a manifest resource (here `oNNFP`): a 2-byte header length, a header XOR'd with the 4 bytes after it, then a body that is DES-CBC encrypted and compressed. The header holds a tag string, encrypted and compressed flags, a signature length, a key flag, the DES key and the IV. The compression is Deflate with a 4-bit block header (1 bit final, 3 bits type: 3 stored, 2 fixed, 4 dynamic) and stored-block lengths XOR'd with `0xF112` and no `NLEN`, so `zlib` can't read it and the tool carries a small inflater. The body is a run of `BinaryReader` strings; each string's ID is `(offset + 22) ^ key`, with the key taken from a Base64 name list in the user-string heap. The remaining strings are fixed-size field blobs decoded with `b ^ ((i * 37 + 107) & 0xFF)`.

The payload blob must end in its own length minus 4. Only the first quarter is used: bytes 32 onward are placed at offset 64 of a buffer and XOR'd with a fixed keystream from a 32-bit shift register (seed `0x95000000`, feedback bit 18 XOR bit 17 into bit 31, MSB first), and the stage-1 size and DLL follow at offsets 64 and 68. The `uid` is 4 hex characters of `GetTickCount() ^ pid` followed by 4 characters that XOR the security-product weight with that prefix and with characters 0–3 and 7–10 of the download token.

Hash tables use 32-bit FNV-1a over ASCII-lowercased names, XOR'd with `0xC6E39BD8`.

## Tested on

| SHA-256 | Result |
|---|---|
| `ecaa3ca51c1e9ec0f81a167909999af9f808515e3c35587955e61c228939aeb0` | 241 resource strings, 32 XOR strings, 4 URLs, 3 resources; `--names` reproduces the 62 hashes resolved in the post |

`--blob` was tested on a synthetic blob built with an independent implementation of the IL, since no real server response is available. `--uid` was tested the same way.

## Credit

The inflater comparison used de4dot's Babel module (`BabelInflater`, `ResourceDecrypter`). NETReactorSlayer by SychicBoy removed the control-flow obfuscation that made the IL readable.
