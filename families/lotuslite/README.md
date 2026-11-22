# Lotuslite V2 (fake PDFgear CommonLib.dll)

Reads a Lotuslite V2 `CommonLib.dll`, the .NET backdoor that Antares Research attributed to Mustang Panda, and prints its built-in configuration as JSON. It also prints the embedded RSA public key's fingerprint and the strings that name the instance lock, the persistence (folder, Run value, task, shortcut) and any in-memory patch targets (`RuntimeInit.Apply`: `EtwEventWrite` and `AmsiScanBuffer` in the 2.1.16.0 build, empty in the others).

Write-up: [Lotuslite V2 talks to port 53 without speaking DNS](https://stateless-re.github.io/2026/lotuslite-v2-pro1/)

## Usage

```sh
python -I extract.py CommonLib.dll [more.dll ...]
```

Needs `dnfile`, `pefile` and `cryptography`. Exit status is 1 if any file fails; that record has an `error` field.

## Output (abridged, from 4748571d...)

```json
    "assembly": {
      "name": "CommonLib",
      "version": "2.1.18.0"
    },
    "xor_key": "0x55",
    "config": {
      "ServerIps": [
        "31.59.184.185",
        "103.175.50.32"
      ],
      "UDPPorts": [
        53
      ],
      "SkipCertValidation": true,
      "EnableLastChannelMemory": false,
      "DefaultCmdPath": "C:\\Windows\\System32\\cmd.exe",
      "StateDir": "C:\\ProgramData\\MSICache"
    },
    "rsa_public_key": {
      "resource": "BeCtrl.Keys.public.pem",
      "bits": 2048,
      "spki_sha256": "544babf3c6485418c35f8db11f1110e70e06af78f690d556beec1d6008eb1df6"
    },
    "strings": {
      "BeCtrlBootstrap.EnsureStarted": [
        "Local\\",
        "Global\\",
        "PDFgear_DeviceSync_Mutex",
        "ConfigSyncWorker"
      ],
```

## How it works

The configuration lives in the static constructor of `BeCtrl.Config.ClientDefaults`. Strings are byte arrays initialised from `<PrivateImplementationDetails>` field data and passed to `ClientDefaults.D`, which XORs each byte with a constant (0x55 in every build so far). The tool reads that constant from `D`'s IL, then runs a small stack evaluator over the constructor's IL (`newarr`, `ldtoken` + `InitializeArray`, `stelem`, `stsfld`, calls to `D`). It does the same for `ClientConfig.FromDefaults`, which sets the booleans and timeouts. Nothing is loaded or executed. The RSA key is the manifest resource `BeCtrl.Keys.public.pem`; the strings are the `ldstr` operands of `BeCtrlBootstrap.EnsureStarted`, every `Persistence` method and `RuntimeInit.Apply`.

## Tested on

| SHA-256 | version | first C2 |
|---|---|---|
| 4748571d98c6af34f4967a3886f73b4421239a1203f048140d3bfdaf8aa78937 | 2.1.18.0 | 31.59.184.185 |
| aa424e71f1c25d2455e14dadae35b380950dd4c73988183e7df88e1ed67e4d27 | 2.1.18.0 | 139.84.169.184 |
| 486119e45dadf2b3bafd974e0ea5e1e8e8bc35be320649bfb03ceb12406e7dcd | 2.1.18.0 | 139.84.169.184 |
| 45095e850d54f5ccf0ca20527ec6f8aed6d5d8eaa3a002255cea06c87627dd48 | 2.1.16.0 | 139.84.169.184 |

All four decode fully; the second C2 is 103.175.50.32 in each, and all share the RSA key above.

## Credit

Kyaw Pyiyt Htet (Mikoyan) and Phyo Paing Htun (ChiLai) of [Antares Research](https://antares-research.com/reports/lotuslite-v2/) described Lotuslite V2 and its 0x55 XOR configuration.
