import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from elftools.elf.elffile import ELFFile

IPV4 = re.compile(rb"^(?:\d{1,3}\.){3}\d{1,3}$")
PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
MIN_LEN = 4
MAX_LEN = 600
MARKERS = {
    "persistence_copy": b"/.cling",
    "proc_bind_mount": b"mount --bind /tmp /proc/",
    "wget_hijack_wrapper": b"wget.wrapper",
    "oom_score_adj": b"/proc/self/oom_score_adj",
    "watchdog": b"/dev/watchdog",
    "tmp_cleanup": b"rm -rf /tmp/cmdline",
    "user_agent_clingwashere": b"clingwashere",
}


def section_bytes(elf: ELFFile, names: tuple[str, ...]) -> list[tuple[str, bytes]]:
    found = []
    for section in elf.iter_sections():
        if section.name in names and section["sh_type"] != "SHT_NOBITS":
            found.append((section.name, section.data()))
    return found


def chacha20(key: bytes, nonce: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.ChaCha20(key, b"\0\0\0\0" + nonce), mode=None)
    return cipher.encryptor().update(data)


def plain_strings(blob: bytes) -> list[str]:
    found = []
    for match in re.finditer(rb"[\x20-\x7e\t\r\n]{%d,}" % MIN_LEN, blob):
        found.append(match.group().decode("latin-1"))
    return found


def printable_run(cipher: bytes, keystream: bytes, limit: int) -> int:
    run = 0
    while run < min(len(cipher), limit) and (cipher[run] ^ keystream[run]) in PRINTABLE:
        run += 1
    return run


def string_end(cipher: bytes, keystream: bytes, depth: int = 2) -> int | None:
    run = printable_run(cipher, keystream, MAX_LEN)
    for length in range(MIN_LEN, run + 1):
        if length >= len(cipher) or cipher[length] != 0:
            continue
        rest = cipher[length + 1 :]
        if not rest or rest[0] == 0:
            return length
        if depth > 0 and string_end(rest, keystream, depth - 1) is not None:
            return length
    return None


def decrypt_strings(rodata: bytes, key: bytes, nonce: bytes) -> list[dict]:
    keystream = chacha20(key, nonce, bytes(MAX_LEN))
    found = []
    offset = 0
    while offset < len(rodata):
        window = rodata[offset : offset + 4 * MAX_LEN]
        if window[:2] == b"\0\0":
            offset += 1
            continue
        end = string_end(window, keystream)
        if end is None:
            offset += 1
            continue
        text = bytes(a ^ b for a, b in zip(window[:end], keystream[:end], strict=True))
        found.append({"offset": offset, "text": text.decode("latin-1")})
        offset += end + 1
    return found


def find_key(elf: ELFFile, rodata: bytes) -> tuple[bytes, bytes, list[dict]] | None:
    best = None
    for _, blob in section_bytes(elf, (".data", ".data.rel.ro", ".rodata")):
        for start in range(0, len(blob) - 44 + 1, 4):
            nonce = blob[start : start + 12]
            key = blob[start + 12 : start + 44]
            if len(set(key)) < 16:
                continue
            probe = decrypt_strings(rodata[:4096], key, nonce)
            score = sum(1 for item in probe if IPV4.match(item["text"].encode()))
            if score >= 3 and (best is None or score > best[0]):
                best = (score, key, nonce)
    if best is None:
        return None
    _, key, nonce = best
    return key, nonce, decrypt_strings(rodata, key, nonce)


def summarize(strings: list[str]) -> dict:
    stun = [s for s in strings if IPV4.match(s.encode()) and s != "8.8.8.8"]
    tags = sorted(
        {t for s in strings for t in re.findall(r"[a-z0-9]+\.selfrep|selfrep\.[a-z0-9]+", s)}
    )
    requests = []
    for s in strings:
        method = re.match(r"^(GET|POST) (/[^? ]*)", s)
        if method:
            requests.append(f"{method.group(1)} {method.group(2)}")
        elif s.startswith("orf;"):
            requests.append("UDP orf; (Realtek UDPServer)")
        elif s.startswith("TCP_MSGHEAD_CMD"):
            requests.append("UDP TCP_MSGHEAD_CMD (KGUARD)")
    requests = sorted(set(requests))
    blob = "\n".join(strings).encode("latin-1")
    markers = sorted(name for name, needle in MARKERS.items() if needle in blob)
    return {
        "stun_servers": stun,
        "stun_server_count": len(stun),
        "uses_8_8_8_8": "8.8.8.8" in strings,
        "selfrep_tags": tags,
        "exploit_targets": requests,
        "markers": markers,
    }


def analyze(path: Path, show_strings: bool) -> dict:
    data = path.read_bytes()
    record: dict = {"file": str(path), "sha256": hashlib.sha256(data).hexdigest()}
    with path.open("rb") as handle:
        elf = ELFFile(handle)
        record["machine"] = elf["e_machine"]
        record["class"] = elf.elfclass
        record["endian"] = "little" if elf.little_endian else "big"
        rodata_parts = section_bytes(elf, (".rodata",))
        if not rodata_parts:
            raise ValueError("no .rodata section")
        rodata = rodata_parts[0][1]
        strings = plain_strings(rodata)
        record["string_encryption"] = None
        if not any(IPV4.match(s.encode()) for s in strings):
            result = find_key(elf, rodata)
            if result is None:
                raise ValueError("no STUN list in plain strings and no ChaCha20 key found")
            key, nonce, decrypted = result
            record["string_encryption"] = {
                "algorithm": "ChaCha20, counter 0, keystream restarts at every string",
                "key": key.hex(),
                "nonce": nonce.hex(),
                "strings_decrypted": len(decrypted),
            }
            strings = [item["text"] for item in decrypted]
    record.update(summarize(strings))
    if not record["stun_servers"]:
        raise ValueError("no STUN server list found")
    if show_strings:
        record["strings"] = strings
    return record


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract the STUN server list, propagation tags, exploit requests and "
        "markers from Cling/ClingSTUN ELF builds; decrypts ChaCha20-encrypted string tables."
    )
    parser.add_argument("files", nargs="+", type=Path, help="Cling ELF files")
    parser.add_argument("--strings", action="store_true", help="include every recovered string")
    args = parser.parse_args()
    failed = False
    results = []
    for path in args.files:
        try:
            results.append(analyze(path, args.strings))
        except (OSError, ValueError) as error:
            failed = True
            results.append({"file": str(path), "error": str(error)})
        except Exception as error:
            failed = True
            results.append({"file": str(path), "error": f"{type(error).__name__}: {error}"})
    json.dump(results, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
