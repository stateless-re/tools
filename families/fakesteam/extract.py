from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

import dnfile
import pefile

MSVC_DOS = bytes.fromhex(
    "4d5a90000300000004000000ffff0000b800000000000000400000000000000000000000000000000000000000000000000000000000000000000000"
)
LLD_DOS = bytes.fromhex(
    "4d5a78000100000004000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000"
)
BLOCK_SIZES = (0, 8, 12, 16, 20, 24, 28, 32)
MAX_KEY = 16
BRIDGE_METHODS = (
    "win.min",
    "win.close",
    "win.drag",
    "win.resize",
    "http.request",
    "fs.readText",
    "fs.writeText",
    "shell.open",
)
URL_HOST = re.compile(r"https?://[0-9]{6,12}\.[a-z0-9-]+\.[a-z]{2,}[\x21-\x7e]*")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strings_ascii(data: bytes, minimum: int = 6) -> list[str]:
    return [m.group().decode() for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minimum, data)]


def strings_utf16(data: bytes, minimum: int = 6) -> list[str]:
    pattern = rb"(?:[\x20-\x7e]\x00){%d,}" % minimum
    return [m.group().decode("utf-16le") for m in re.finditer(pattern, data)]


def interleaved_order(block: int, length: int) -> list[int]:
    if block == 0:
        return list(range(length))
    half = block // 2
    order = []
    for start in range(0, length, block):
        order += [start + 2 * j for j in range(half)]
        order += [start + 2 * j + 1 for j in range(half)]
    return order


def stored_template(template: bytes, block: int) -> bytes:
    usable = len(template) - len(template) % max(block, 1)
    order = interleaved_order(block, usable)
    return bytes(template[k] for k in order)


def decode(data: bytes, offset: int, size: int, key: bytes, block: int) -> bytes:
    raw = data[offset : offset + size]
    plain = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
    if block == 0:
        return plain
    out = bytearray(len(plain))
    order = interleaved_order(block, len(plain) - len(plain) % block)
    for stored, original in enumerate(order):
        out[original] = plain[stored]
    out[len(order) :] = plain[len(order) :]
    return bytes(out)


def pe_size(image: bytes) -> int | None:
    try:
        pe = pefile.PE(data=image, fast_load=True)
    except pefile.PEFormatError:
        return None
    ends = [s.PointerToRawData + s.SizeOfRawData for s in pe.sections]
    size = max([*ends, pe.OPTIONAL_HEADER.SizeOfHeaders])
    security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    if security.VirtualAddress and security.Size:
        size = max(size, security.VirtualAddress + security.Size)
    return size


def xor_bytes(left: bytes, right: bytes) -> bytes:
    size = min(len(left), len(right))
    value = int.from_bytes(left[:size], "little") ^ int.from_bytes(right[:size], "little")
    return value.to_bytes(size, "little")


def candidate_offsets(data: bytes, stored: bytes, length: int) -> list[int]:
    width = len(stored) - length
    pattern = xor_bytes(stored[:width], stored[length:])
    shifted = xor_bytes(data[:-length], data[length:])
    hits = []
    position = shifted.find(pattern)
    while position != -1:
        hits.append(position)
        position = shifted.find(pattern, position + 1)
    return hits


def try_offset(data: bytes, offset: int, stored: bytes, length: int, block: int) -> dict | None:
    window = data[offset : offset + length]
    key = xor_bytes(window, stored[:length])
    if len(window) < length or not any(key):
        return None
    head = decode(data, offset, 0x400, key, block)
    if pe_size(head + b"\0" * 0x1000) is None:
        return None
    size = pe_size(decode(data, offset, 0x1000000, key, block))
    if not size or offset + size > len(data):
        return None
    image = decode(data, offset, size, key, block)
    return {
        "offset": offset,
        "size": size,
        "xor_key": key.hex(),
        "interleave_block": block,
        "sha256": sha256(image),
        "image": image,
    }


def carve_xor_pes(data: bytes) -> list[dict]:
    found: list[dict] = []
    for template in (MSVC_DOS, LLD_DOS):
        for block in BLOCK_SIZES:
            stored = stored_template(template, block)
            for length in range(1, MAX_KEY + 1):
                for offset in candidate_offsets(data, stored, length):
                    if any(f["offset"] <= offset < f["offset"] + f["size"] for f in found):
                        continue
                    item = try_offset(data, offset, stored, length, block)
                    if item is not None:
                        found.append(item)
    return found


def webview_switches(texts: list[str]) -> list[str]:
    for text in texts:
        if "--ignore-certificate-errors" in text or "--disable-features=" in text:
            return text.split()
    return []


def phishing_urls(texts: list[str]) -> list[str]:
    urls = set()
    for text in texts:
        for match in URL_HOST.finditer(text):
            if "microsoft" not in match.group() and "llvm" not in match.group():
                urls.add(match.group())
    return sorted(urls)


def dotnet_info(path: Path) -> dict | None:
    try:
        pe = dnfile.dnPE(str(path))
    except Exception:
        return None
    if pe.net is None:
        return None
    resources: dict[str, bytes] = {}
    for resource in pe.net.resources or []:
        name = str(resource.name)
        payload = resource.data
        if isinstance(payload, (bytes, bytearray)):
            resources[name] = bytes(payload)
            continue
        for entry in getattr(payload, "entries", []) or []:
            if isinstance(entry.data, (bytes, bytearray)):
                resources[f"{name}!{entry.name}"] = bytes(entry.data)
    texts: list[str] = []
    heap = pe.net.user_strings
    offset = 1
    while heap is not None and offset < heap.sizeof():
        try:
            item = heap.get(offset)
        except Exception:
            break
        if item is None or item.raw_size is None:
            break
        if item.value:
            texts.append(item.value)
        offset += item.raw_size
    return {"resources": resources, "texts": texts}


def strip_length_prefix(blob: bytes) -> bytes:
    if len(blob) > 4 and int.from_bytes(blob[:4], "little") == len(blob) - 4:
        return blob[4:]
    return blob


def analyse(path: Path, outdir: Path | None) -> dict:
    data = path.read_bytes()
    record: dict = {"file": str(path), "sha256": sha256(data)}
    embedded: list[dict] = []
    net = dotnet_info(path)
    texts = strings_ascii(data) + strings_utf16(data)
    if net is not None:
        texts += net["texts"]
        for name, blob in net["resources"].items():
            body = strip_length_prefix(blob)
            if body[:2] == b"MZ":
                embedded.append(
                    {"resource": name, "size": len(body), "sha256": sha256(body), "image": body}
                )
        record["kind"] = "dotnet"
    else:
        record["kind"] = "native"
    record["phishing_urls"] = phishing_urls(texts)
    record["webview2_switches"] = webview_switches(texts)
    record["bridge_methods"] = [m for m in BRIDGE_METHODS if m in texts or m in "\n".join(texts)]
    record["restore_trigger"] = any("steamcommunity.com" in t for t in texts)
    record["steam_back"] = any("steam.back" in t for t in texts)
    embedded += carve_xor_pes(data)
    for item in embedded:
        image = item.pop("image")
        if outdir is not None:
            target = outdir / item["sha256"]
            target.write_bytes(image)
            os.chmod(target, 0o600)
    record["embedded_pes"] = embedded
    if not (record["phishing_urls"] or record["steam_back"] or embedded):
        record["error"] = "no fake Steam client, restorer or loader traits found"
    return record


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Static triage of fake Steam client builds, their steam.exe restorer and loader"
    )
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument(
        "-o", "--outdir", type=Path, help="write embedded PEs here, named by SHA-256"
    )
    args = parser.parse_args()
    if args.outdir:
        args.outdir.mkdir(parents=True, exist_ok=True)
    failed = False
    for path in args.files:
        try:
            record = analyse(path, args.outdir)
        except Exception as exc:
            record = {"file": str(path), "error": str(exc)}
        failed |= "error" in record
        print(json.dumps(record, ensure_ascii=False))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
