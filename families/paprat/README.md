# PapRAT (C++) config extractor

Extracts the C2 configuration of BITTER's C++ PapRAT from the PE or from the MSI that carries it in its `Binary` table. It finds the XOR loop in the code, reads the key and the skip set from it, and decodes every string passed to it.

## Usage

```sh
python extract.py SAMPLE.msi [SAMPLE.exe ...]
```

## Output (abridged)

```json
{
  "sha256": "569a21b519aaac8c92f653d708ab6ef34e3f38ea967f47e041d1e2425f6a4b33",
  "payloads": [
    {
      "sha256": "a16f17c204840df2b06c431887ad2f0c5b62b3c92cd601010b439f8715a7b24c",
      "decoder": {"va": "0x40d660", "xor_key": "0x50", "skip": ["0x0", "0xa", "0x50", "0x5a"]},
      "c2": {
        "host": "www.rivingtonclarks.com",
        "port": 80,
        "paths": ["/beautiQuewonders", "/beautiQuewonders/banaNa.php", "/receive.php"]
      },
      "commands": ["msg", "FDD", "UPP", "DWW", "DEL", "RUN", "GDR", "SS1"],
      "otp_literals": ["123456"],
      "client_id_default": "NULL_NULL",
      "origin": "Binary._2E9D1C8BAC5D0F288E61BF5987C52203"
    }
  ]
}
```

## How it works

The decoder is `out[i] = in[i]` when `in[i]` is 0x00, 0x0A, 0x5A or 0x50, and `in[i] ^ 0x50` otherwise. The extractor locates the `xor al, imm8; mov [ecx+edx], al` store, collects the `cmp byte ptr [ecx+edx], imm8` checks before it as the skip set, and walks back to the function prologue. For every `call` to that function it disassembles the preceding bytes and takes the last pushed address inside the image as the encoded string, and the push before it as the length when there is one. MSI stream names are decoded from the Windows Installer packed form.

The OTP value is the wide literal of six digits the upload, download and screenshot handlers send in the `OTP:` header.

## Tested on

| SHA-256 | File | Result |
|---|---|---|
| `569a21b519aaac8c92f653d708ab6ef34e3f38ea967f47e041d1e2425f6a4b33` | MSI | config above |
| `a16f17c204840df2b06c431887ad2f0c5b62b3c92cd601010b439f8715a7b24c` | PapRAT PE from the MSI | same config |

The Rust build Fortinet describes uses a different encoding (reversed, ROT-3) and is not handled.

## Credit

Fortinet FortiGuard Labs (Cara Lin), [BITTER Expands Its Arsenal with PapRAT](https://www.fortinet.com/blog/threat-research/bitter-expands-its-arsenal-with-paprat), documented the family, the XOR 0x50 config and the command set.

Write-up: [PapRAT's one-time password is 123456](https://stateless-re.github.io/2026/paprat-otp/)
