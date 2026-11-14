# CerealLoader

Static config extractor for CerealLoader, the mixed-mode (C++/CLI) .NET loader in Turla's Cereal toolset. It prints the payload and error-log paths, the payload cipher and key, the export-proxy target, the VTableFixup slots behind the native entry point, the RC4-encrypted string in the native code of the CcmEval build, and what survives of each build's original, pre-ConfuserEx metadata.

Write-up: [Turla's CerealLoader still carries its unobfuscated metadata](https://stateless-re.github.io/2026/cerealloader-original-metadata/)

## Usage

```sh
python extract.py LOADER.dll [LOADER2.dll ...]
python extract.py LOADER.dll --payload ENCRYPTED_FILE -o outdir
```

`--payload` decrypts an encrypted payload file with the first loader's scheme and writes the result to `outdir`, named by its SHA-256, mode 600. Nothing is loaded or run.

Requires `pefile`, `dnfile` and `capstone`.

## Output (abridged, `Microsoft.Ceres.dll`)

```json
{
  "sha256": "41164eb06adc72b187edaf90d73ca73be729d4ebfdecf57d7398561136941651",
  "pe_timestamp": "2024-08-21T00:42:15+00:00",
  "linker": "14.50",
  "clr": {"flags": "0x10", "native_entry_point": true, "native_entry_rva": "0x29c0", "vtable_fixups": ["..."]},
  "exports": {"dll_name": "SensApi.dll", "count": 3, "forwarded": 3, "forward_targets": ["C:\\Windows\\System32\\SensApi.dll"]},
  "import_count": 74,
  "cipher": "rc4",
  "rc4_key": "cbfd80a01fe596206d34e1ab703ae5dc...",
  "strings": [
    "c:\\\\Windows\\\\CCM\\\\SystemTemp\\\\685713b14b62",
    "c:\\\\Windows\\\\CCM\\\\SystemTemp\\\\685713b14b63",
    "Failed to find method",
    "Failed to find assembly",
    "Failed to find type"
  ],
  "native_paths": ["c:\\WINDOWS\\CCM\\SystemTemp\\68571"],
  "original_metadata": {
    "metadata_rva": "0x4520",
    "active_metadata_rva": "0x116f4",
    "methods": ["import_functions", "Encrypt", "O8iHWV3", "L3kuz3rOr3t2", "a12MHqz782R0od"],
    "managed_entry_points": ["import_functions", "a12MHqz782R0od"],
    "native_import_pointers": 56,
    "cpp_literals": ["c:\\WINDOWS\\CCM\\SystemTemp\\68571", "NtTerminateProcess", "ntdll.dll", "1", "3", "4"],
    "user_strings": []
  },
  "native_rc4_strings": ["CcmEval"]
}
```

The first decrypted path in `strings` is the payload in every build tested; the second, when present, is the error log. Doubled backslashes are in the decrypted strings themselves.

## How it works

The tool reads IL and native code directly; no decompiler. ConfuserEx's control-flow flattening scatters each byte array over many switch cases as `ldloc; ldc idx; ldc val; stelem.i1`, so the tool finds every `newarr System.Byte` and its local slot, then applies all element stores to that slot in a second pass (the flattening puts some stores before the allocation in IL order). A 256-byte array is the RC4 key for the rest; without one, arrays longer than 255 bytes are decoded as `[255-byte key][data XOR key]`. The 2024 build hides its one string with ConfuserEx's constants protection: the tool tries every `ldc.i4` value in the module as the xorshift seed until a FieldRVA blob decrypts to valid LZMA, then decodes IDs with the multiply/XOR pairs from the generic getter methods. The native string in the CcmEval build is built on the stack with `mov dword ptr [rsp/rbp+x], imm32`; the tool rebuilds the frame, finds the managed RC4 key in it, and decrypts what's left.

Four of the five builds still contain the metadata root that MSVC wrote before ConfuserEx appended its own. The CLI header points at the new one; the tool finds the other `BSJB` signature, points a copy of the header at it in memory, and reads method names, `__m2mep@` managed entry points, `__unep@` native import pointers, C++ string literals and the `#US` heap. To decompile the original code, write that patched copy to disk and open it in ILSpy.

## Tested on

| SHA-256 | Name (ESET) | Result |
|---|---|---|
| `13fe1eb9b182b076a815f84d34b66365809d0cff32df6f5b85aa7ef4deee98e0` | Microsoft.Exchange.Data.Transport.ni.dll | 32-byte key-prefix XOR; path `C:\ProgramData\Microsoft\Vault.fsc`; no original metadata |
| `241aac14756a0f29edd084b858623db259d59c77ea44889de93431c42ff10036` | version.dll | 255-byte key-prefix XOR; ConfuserEx constant decoded; original metadata (`ManagedEntryPoint`, `Xor`) |
| `d3b6065eb001d169421fcd146f64b087055dadebd973d8d69ae2bf97fbf288e2` | version.dll | 255-byte key-prefix XOR; payload and log paths; original metadata |
| `6119d25ae51d04264384f5d738c104e42596b0774609666b357a43608a48404c` | Microsoft.Search.Platform.dll | RC4; payload and log paths; original metadata with 57 import pointers |
| `41164eb06adc72b187edaf90d73ca73be729d4ebfdecf57d7398561136941651` | Microsoft.Ceres.dll | RC4; payload, log and native paths; `CcmEval`; original metadata with 56 import pointers |

`--payload` was tested with synthetic files encrypted under each of the three schemes; no real payload was available.

## Credit

ESET Research (Matías Porolli), [Exchange for breakfast: Turla's Cereal tricks are not for kids](https://www.welivesecurity.com/en/eset-research/exchange-for-breakfast-turlas-cereal-tricks-are-not-for-kids/), and the [IoC list](https://github.com/eset/malware-ioc/tree/master/turla) the hashes came from. R136a1 identified CerealLoader as C++/CLI and published a [proof of concept](https://gist.github.com/TheEnergyStory/b4efad6170b06c5b3267c7e37927fa1d).
