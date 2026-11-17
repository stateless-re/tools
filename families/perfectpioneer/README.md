# PerfectPioneer RAT delivery chain

Static unpacker for the PerfectPioneer RAT (TGR-STA-0049) delivery chain: the Go installer that embeds a signed `phoneactivate.exe` and a proxy DLL, the proxy loaders (`SLC.dll`, `vrfcore.dll`, `WTSAPI32.dll`), the `INJECT_01` container hidden after the Authenticode signature, the reflective stub, and the Go agent. For every file it prints what it is, what it carries, and the agent's C2 URL, username and password where the agent passes them to `agent.NewClient`.

Write-up: [PerfectPioneer's phoneactivate.exe is unmodified Microsoft code with the RAT in its signature](https://stateless-re.github.io/2026/perfectpioneer-signed-phoneactivate/)

## Usage

```sh
python extract.py FILE [FILE ...]
python extract.py INSTALLER.exe -o outdir
```

`-o` writes every embedded or carved PE to `outdir`, named by its SHA-256, mode 600. Nothing is loaded or run. Exit status is 1 if a file shows none of the chain's traits.

Requires `pefile` and `capstone`; `lief` is used, if installed, to check whether a host's Authenticode digest still matches.

## Output (signed host `52d3442f`, abridged, and loader `2e52b293`)

```json
{
  "file": "52d3442fb26023ebc0bc76542b56be88d1c3327c8bcedf1dcb95f80511527f07",
  "kind": "signed_host",
  "signature_digest_matches": true,
  "children": [
    {
      "kind": "shellcode",
      "sha256": "64230ef10e64df84509276b531a7b148aaca6a4051737bf7a80c1a3a56d61bc3",
      "size": 7302889,
      "offset": 133733,
      "xor_key": 0,
      "marker": "INJECT_01",
      "name": "code.bin",
      "declared_size": 7302889,
      "stub_size": 4841,
      "stub_strings": ["GetProcAddress", "LoadLibraryA", "VirtualAlloc"],
      "children": [
        {
          "kind": "go",
          "sha256": "183abf82951c2052e9a1829c70c173c11756e8df0e86c8071c27df0988caeaa0",
          "project": "D:/proj/http3/rat_http3_cc",
          "module": "pioneer",
          "config": {
            "url": "https://ads-edge.com:36897",
            "username": "dhsfhakhaskjyuiashfhasjkdfhjkh",
            "password": "askjdfklsagklhkhzokhfd"
          }
        }
      ]
    }
  ]
}
{
  "file": "2e52b2936e67872d1364d2d0d26a8733ed9582b38f6f0b3a877ffdd6e2c04aa4",
  "kind": "loader",
  "host_file": "phoneactivate.exe",
  "read_offset": 133733,
  "read_size": 7302889,
  "xor_key": 0,
  "run_value": "WindowsSecurityUpdate",
  "trigger_exports": ["SLOpen"],
  "export_dll_name": "MFSENSORGROUP.dll",
  "timestamp": 1760435424
}
```

## How it works

The signed `phoneactivate.exe` keeps Microsoft's code and a matching Authenticode digest; the payload is appended inside the certificate table after the PKCS#7 blob, where the digest doesn't cover it. The container is `INJECT_01`, a 32-byte NUL-padded name, a 4-byte little-endian size and the code. The tool parses the security directory, skips the DER signature, finds the marker (also after XOR with `0xAA`), and looks for `MZ 90 00 03 00` in the code, which is where the stub starts mapping. The stub's API names are stack strings stored 0x10 higher; the tool decodes them as a sanity check. Loaders are recognised by their imports (`SetFilePointer`, `ReadFile`): the offset and size are the immediates passed to `SetFilePointer` and `VirtualAlloc`, the key is the byte in the trailing `xor byte ptr [reg], imm8` loop, and the trigger export is the one whose stub isn't `ret`. Installers are Go binaries with more PEs embedded in their `.rdata`. Agent configs come from the call to `internal/agent.NewClient` in `main.main`: the three (pointer, length) string pairs in `rax/rbx`, `rcx/rdi` and `rsi/r8`. Other variants only get their URL strings with an explicit port.

## Tested on

All from Unit 42's indicator list, downloaded from Hybrid Analysis, except `183abf82`, which the tool also carves from the hosts and installers.

| SHA-256 | Result |
|---|---|
| `d700b573ea8387efad633a70124b7a2a3aece844a267157b1cb55be7b62f3b67` | go_dropper: loader 2e52b293, host 52d3442f, agent config |
| `fb5b0b1d083d6f6afa90948bd1fd1a498b51dd3f6dc7f90a02a2a17818756563` | go_dropper: loader 2e52b293, host 904409ce, agent config |
| `52d3442fb26023ebc0bc76542b56be88d1c3327c8bcedf1dcb95f80511527f07` | signed_host, digest matches, INJECT_01, agent config |
| `904409ce8846394e1fe9a5ce37f2265cbf6933611278ae57fdf5fa74759af2bb` | signed_host, digest broken, INJECT_01, agent config |
| `2e52b2936e67872d1364d2d0d26a8733ed9582b38f6f0b3a877ffdd6e2c04aa4` | loader: phoneactivate.exe, 0x20a65, 0x6f6ee9, no XOR |
| `8cfe629fc08ae06c8ba106113ba30bb16fa2fbbf8bd3dd6831d16b031e0ebe70` | loader (x86): phoneactivate.exe, 0x1bbe5, 0x10fdbf, no XOR |
| `9dfefc7118646535d1193e1b036dd0c93fa66cc585a60301fcdceb6f45903aad` | loader: appverif.exe, 0x27f08, 0x2beae9, XOR 0xAA |
| `600572a912650b258d56aedeef0ab712abbe35a38cdd23faa5a95dacfdc67b7f` | loader: own executable, 0x20a38, 0x76a4e9, XOR 0xAA |
| `24c46bc9269e1c1ee54004e01d5c7c54f759bc1b93a282d3561d2d27f678af86` | loader: own executable, 0xf5bb8, 0x76a4e9, XOR 0xAA |
| `f82c06184ab36e91d28f7802c739e637792c241a7ff2fba9ca24178f12423684` | loader: own executable, 0xf5bb8, 0xabd6e9, XOR 0xED |
| `183abf82951c2052e9a1829c70c173c11756e8df0e86c8071c27df0988caeaa0` | rat_http3_cc agent config |
| `619b749e1c6634d38f15c51005a4237e9076aaaf36927b562a990e8bc34fdfcb` | rat_http3_cc agent (memory image) config |
| `8bf9401990d3255d1022a25884b02ee75ef01bd1a729d29ff52de2e5f0d637a2` | Pioneer agent config |
| `5805cb5b0a6fb738ef7c1873b8e5de4281c36c7f440f28717fa9f441c5e0ef17` | newhttp3, URL string |
| `5b7effbf0465c05e8dc9a8fea69b000a78237735ea0b854e8d9baee5b7af8344` | newhttp3, URL string |
| `7541222a1316ec54bf9c8660b923e1d0490a925b2ee92060b1567be7cb1bde4b` | newhttp3, URL string |
| `a6a9ccffadd00b0e75e913b0f851b1f834fd20588df8b89759d9ae49a48c8e10` | newhttp3, URL string |
| `cd8f43da32849584751eec884cf7e3208eb0a71108197a32e9bb248612e757d2` | newhttp3, URL string |
| `cffcd6f2589d3ab4f3693805d1752b7c328a00cc543dd02b129763e179c3f311` | newhttp3, URL string |
| `92fb9545ea49e2fb4635fce1859ff3f609738be75f85d146614243fc8bc80b67` | rat_http3_ls, URL string |
| `9721d65ee7695db2b3dc3705f5d8e5efe3a478c3b6d1704d66daf77fe95aeb0d` | RatAAkk-tt, URL string |
| `d725ad8b523c94f99fca9e72a650e835dca47b9ebe7610d6c4eb3525d410c365` | RatAAkk-tt, URL string (private IP) |
| `f4c9d5d13c1a09533876a02f6fa04831efbf600b05cfb3ed765a0ebde82b0457` | PerfectRat, URL string |
| `bf8afbd1c2074c7cd6ff8b86dbe67a57ca5594817e46b24e226b71c4edde7697` | Go agent without project path, URL string |
| `c4b4647795567ab15528edd1ab1bf37fb50e21b442e59a653051061973e87c02` | Go agent without project path, no URL found |

## Credits

Unit 42 (Tom Fakterman), [QUIC and Covert: Novel HTTP/3-Powered RATs Target Southeast Asian Governments](https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/), for the family, its variant names and the indicator list.
