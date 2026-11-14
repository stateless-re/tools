# x.cpe (XCPE botnet)

Static extractor for `x.cpe`, the preinstalled Android TV-box agent behind the XCPE botnet. For each APK it reports the signer (and whether it is the public AOSP test platform key), the AES key x.cpe uses for its `/router/config/*` bodies, the hard-coded hosts and the MQTT topic list. Where a build carries the hidden MzSDK loader (`com/ocean/zoe/letu.jet`), it decodes the loader's StringFog strings, decrypts the embedded core jar and reads its C2 URLs and AES key.

It also decrypts the two traffic formats, so a capture or a sinkhole log can be read without the APK.

## Usage

```sh
pip install androguard cryptography
python extract.py apk X.CPE.apk [MORE.apk ...] [-o OUTDIR]
python extract.py config '{"encryption":"<base64>"}'
python extract.py config-encrypt '{"sn":"...","chipId":"..."}'
python extract.py sdk <hex body from dcsdk.100ulife.com>
```

`-o` writes the decrypted core jar, named by its SHA-256, mode 600. The `config` and `sdk` modes take `--key` if a build ever changes key.

## Example (abridged)

```json
{
  "sha256": "6a995ad8cf248875b47f9d89518c7a21ec7cce2c252c181414e8935c6001ea36",
  "package": "x.cpe",
  "version_name": "6.5.0",
  "shared_user_id": "android.uid.system",
  "signers": [
    {
      "sha1": "27196e386b875e76adf700e7ea84e4c6eee33dfa",
      "aosp_test_platform_key": true
    }
  ],
  "config_cipher": "AES/CFB/NoPadding",
  "config_key": "Iz4iWGbzcm2pHjSm",
  "hosts": [".szbboys.com", "bmw.bestipip.com:16000"],
  "mqtt_topics": ["apps/read", "apps/report", "apps/usage/report", "..."],
  "sdk": {
    "resource": "com/ocean/zoe/letu.jet",
    "xor_key": "letu",
    "jar_sha256": "49e9aaefcb01d69433430e6039a9492f731da7cc456f56070ec697e6fb397488",
    "builtin_version": 39,
    "stringfog": {
      "a": "https://dcsdk.100ulife.com/sdk",
      "r": "com.sun.galaxy.lib.OceanInit",
      "x": "DE252F9AC7624D723212E7E70972134D"
    },
    "core": {
      "urls": [
        "https://dcsdk.100ulife.com/",
        "https://dcsdk.100ulife.com/pluginsync",
        "https://dcsdk.100ulife.com/reportcomp",
        "https://dcsdk.100ulife.com/sdk"
      ],
      "aes_key": "DE252F9AC7624D723212E7E70972134D",
      "entry_class": "com.sun.galaxy.lib.OceanInit"
    }
  }
}
```

## How it works

x.cpe wraps every request to and response from its configuration server (`/router/config/*`, or `/cpe/config/*` in 6.5.0) as `{"encryption": base64(AES-128-CFB(json))}`, with the 16-byte ASCII string `Iz4iWGbzcm2pHjSm` as both key and IV. The extractor reads the key from the static initializer of `x.cpe.util.EncryptUtils` rather than assuming it.

The MzSDK shell (`com.ocean.zoe`) hides its strings with StringFog, but passes the charset name `UTF-8` where the XOR key belongs, so every string is `base64` XORed with the 5 bytes `UTF-8`. The extractor pairs each `const-string` with the static field it lands in. The embedded core `letu.jet` is the jar XORed with `letu` (the resource's file stem). The core asks `dcsdk.100ulife.com` for core updates and plugin lists (the files come from URLs in its answers) with AES-256-ECB (PKCS#5), the key being the 32 ASCII characters `DE252F9AC7624D723212E7E70972134D`, and sends and receives uppercase hex.

The `config` and `sdk` decrypt modes are tested by round trip against the scheme reconstructed from the code. No captured traffic was available to test them on.

## Tested on

| SHA-256 | Version | Signer SHA-1 | MzSDK |
|---|---|---|---|
| 6a995ad8cf248875b47f9d89518c7a21ec7cce2c252c181414e8935c6001ea36 | 6.5.0 | 27196e38 (AOSP test platform key) | yes |
| 5ae5df84cdce0100eb957cf235d1f3fd85fa634592e7ca137de12535e9f8ad2a | 6.5.7 | 27196e38 (AOSP test platform key) | no |
| 07b511a6f7715ccd2f77b5f51e4cf46542ccaada99564252711f4a142ac26179 | 6.6.0 | 27196e38 (AOSP test platform key) | yes |
| 5e9e0f8dc96fbf4d3e78dae90d434c424045c823316dea394e3ca39d97cda9bb | 6.6.0 | a48cd72e | yes |
| 539913c9769de4c60151fd0c4dc5d5a669fbd48b64194b727f2f46e512e74b3f | 6.8.3 | 27196e38 (AOSP test platform key) | no |
| 6f7f4b22eb7841d2b828f1eda77173880d42267a33b387bee9cee983c03bf291 | 6.8.5 | 64be9010 | no |
| 1de0a368599ab04b8863c0e61c2d5a75e00f742a3326325f2870a9a72ee8d200 | 6.8.6 | 64be9010 | no |
| c96e32f7cbb8dda3cfb1f94f2c3d51dbcb68e2e5879093e18385f0b8f3b1a63b | 6.8.6 | a48cd72e | no |

All eight report the same config key. The three MzSDK builds carry the same `letu.jet` (`be9d36d8…`) and decrypt to the same core jar (`49e9aaef…`). The tool also runs on `com.abc.nexus` 1.5.3 (`a552bcb7…`) and correctly reports no x.cpe config key and no MzSDK.

## Credit

Samples from TrendAI Research's [IoC list](https://www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/trendaitm-research-helps-disrupt-android-tv-botnet-of-more-than-13-million-pre-infected-devices), downloaded from Hybrid Analysis. Background on the botnet: Google Threat Intelligence Group, [Shutting the Door on the XCPE Botnet](https://cloud.google.com/blog/topics/threat-intelligence/shutting-the-door-on-the-xcpe-botnet). Write-up: [stateless](https://stateless-re.github.io/2026/xcpe-mzsdk-loader/).
