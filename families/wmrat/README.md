# WmRAT C2 decoder

Decodes the C2 host, port and string transform of BITTER's WmRAT. Each build seen so far uses a different string transform, so the tool tries the three shapes observed and reports which one turns an `.rdata` string into a host name.

## Usage

```sh
python extract.py SAMPLE.exe [...] [--strings]
```

`--strings` also decodes every `.rdata` string with the transform found.

## Output (abridged, four builds)

```text
811741d9df51  uxmesysconsole.com  out[i] = in[i] - 0x2e                     port 80
10cec5a84943  academymusica.com   out[i] = in[i] - 0x25                     port 47408
411c0b9a2f98  netmansrvdns.com    out[i] = in[i] - min(i - 1, 10) - 0x29    port 39186
e6b523e77c31  ashersoftlib.com    out[i] = (in[i] ^ i) - 0x14               port 44908
```

Each record is JSON with `sha256`, `compiled` (PE timestamp), `c2` (address of the encoded string, host, transform, key, formula) and `ports`.

## How it works

Every NUL-terminated `.rdata` string of 6 to 80 bytes is run through three transform families with every key from 1 to 255: a flat subtraction, a subtraction that grows with the index up to 10, and an XOR with the index followed by a subtraction. A result that is a host name or IPv4 address is reported. The port is the operand of the call to `htons` (WS2_32 ordinal 9): either an immediate push or a word loaded from a global.

A build with a new transform shape returns an error rather than a guess.

## Tested on

| SHA-256 | Compiled | Result |
|---|---|---|
| `811741d9df51a9f16272a64ec7eb8ff12f8f26794368b1ff4ad5d30a1f4bb42a` | 2023-05-11 | uxmesysconsole.com:80 |
| `10cec5a84943f9b0c635640fad93fd2a2469cc46aae5e43a4604c903d139970f` | 2024-09-13 | academymusica.com:47408 |
| `411c0b9a2f98b927d806a685faf0c1ab1005647b4816157008892347fb88546b` | 2026-01-23 | netmansrvdns.com:39186 |
| `e6b523e77c31b89f8eb3489007bf14b3b9d34bc3870a9d96ecf7b99efa506c76` | 2026-02-03 | ashersoftlib.com:44908 |

## Credit

- Proofpoint, [Hidden in Plain Sight: TA397's New Attack Chain Delivers Espionage RATs](https://www.proofpoint.com/us/blog/threat-insight/hidden-plain-sight-ta397s-new-attack-chain-delivers-espionage-rats): WmRAT's commands and the subtract-0x25 strings of 10cec5a8.
- Elshinbary, Attfield, Klinger and Wagner, [The Bitter end](https://www.virusbulletin.com/uploads/pdf/conference/vb2025/papers/The-Bitter-end-unravelling-8-years-of-APT-antics.pdf) (VB2025): BITTER's toolset, and the note that WmRAT strings use subtraction in some builds and addition in others.
- Fortinet FortiGuard Labs, [BITTER Expands Its Arsenal with PapRAT](https://www.fortinet.com/blog/threat-research/bitter-expands-its-arsenal-with-paprat): the 411c0b9a build as a PapRAT download.

Write-up: [PapRAT's one-time password is 123456](https://stateless-re.github.io/2026/paprat-otp/)
