import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

import olefile
import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM

XOR_STORE = re.compile(rb"\x34(.)\x88\x04\x11", re.DOTALL)
SKIP_COMPARE = re.compile(rb"\x80\x3c\x11(.)\x74", re.DOTALL)
PROLOGUE = b"\x55\x8b\xec"
WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
MARKERS = {
    "boundary": b"----BoostBoundary",
    "otp_header": b"OTP: ",
    "client_id_header": b"ClientID: ",
    "next_data_key": b"next_data",
}
COMMANDS = ("msg", "FDD", "UPP", "DWW", "DEL", "RUN", "GDR", "SS1")
MSI_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"
OTP_LITERAL = re.compile(rb"\x00((?:[0-9]\x00){6})\x00\x00")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def msi_stream_name(name: str) -> str:
    out = []
    for char in name:
        code = ord(char)
        if code == 0x4840:
            out.append("!")
        elif 0x3800 <= code < 0x4800:
            code -= 0x3800
            out.append(MSI_ALPHABET[code & 0x3F] + MSI_ALPHABET[(code >> 6) & 0x3F])
        elif 0x4800 <= code < 0x4840:
            out.append(MSI_ALPHABET[code - 0x4800])
        else:
            out.append(char)
    return "".join(out)


def pe_payloads(data: bytes) -> list[tuple[str, bytes]]:
    if data[:2] == b"MZ":
        return [("file", data)]
    if not olefile.isOleFile(data):
        return []
    found = []
    with olefile.OleFileIO(data) as ole:
        for entry in ole.listdir(streams=True, storages=False):
            stream = ole.openstream(entry).read()
            if stream[:2] == b"MZ":
                found.append(("/".join(msi_stream_name(e) for e in entry), stream))
    return found


def find_decoder(pe: pefile.PE, text: bytes, text_va: int) -> dict | None:
    for match in XOR_STORE.finditer(text):
        window_start = max(0, match.start() - 0x80)
        window = text[window_start : match.start()]
        skips = [m.group(1)[0] for m in SKIP_COMPARE.finditer(window)]
        if len(skips) < 2:
            continue
        start = text.rfind(PROLOGUE, 0, match.start())
        if start < 0 or match.start() - start > 0x100:
            continue
        return {
            "va": text_va + start,
            "key": match.group(1)[0],
            "skip": sorted(set(skips)),
        }
    return None


def decode(blob: bytes, key: int, skip: list[int]) -> bytes:
    return bytes(b if b in skip else b ^ key for b in blob)


def read_at(pe: pefile.PE, va: int, size: int | None) -> bytes:
    base = pe.OPTIONAL_HEADER.ImageBase
    if size is not None:
        return pe.get_data(va - base, size)
    raw = pe.get_data(va - base, 0x200)
    return raw.split(b"\x00", 1)[0]


def in_image(pe: pefile.PE, va: int) -> bool:
    rva = va - pe.OPTIONAL_HEADER.ImageBase
    return any(s.contains_rva(rva) for s in pe.sections)


def call_sites(text: bytes, text_va: int, target: int) -> list[int]:
    sites = []
    for offset in range(len(text) - 5):
        if text[offset] != 0xE8:
            continue
        rel = struct.unpack_from("<i", text, offset + 1)[0]
        if text_va + offset + 5 + rel == target:
            sites.append(offset)
    return sites


def pushed_string(
    pe: pefile.PE, text: bytes, text_va: int, site: int
) -> tuple[int, int | None] | None:
    disasm = Cs(CS_ARCH_X86, CS_MODE_32)
    disasm.detail = True
    for back in (0x60, 0x50, 0x40, 0x30):
        start = max(0, site - back)
        instructions = list(disasm.disasm(text[start:site], text_va + start))
        if not instructions or instructions[-1].address + instructions[-1].size != text_va + site:
            continue
        pushes = [
            i.operands[0].imm & 0xFFFFFFFF
            for i in instructions
            if i.mnemonic == "push" and i.operands and i.operands[0].type == X86_OP_IMM
        ]
        for index in range(len(pushes) - 1, -1, -1):
            if pushes[index] > 0x10000 and in_image(pe, pushes[index]):
                length = pushes[index - 1] if index and pushes[index - 1] < 0x400 else None
                return pushes[index], length
        return None
    return None


def classify(text: str) -> str:
    if text.isdigit():
        return "port"
    if re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text):
        return "host"
    if text.startswith("/"):
        return "path"
    return "string"


def analyse_pe(data: bytes) -> dict:
    pe = pefile.PE(data=data, fast_load=True)
    text_section = next(s for s in pe.sections if s.Name.startswith(b".text"))
    text = text_section.get_data()
    text_va = pe.OPTIONAL_HEADER.ImageBase + text_section.VirtualAddress
    decoder = find_decoder(pe, text, text_va)
    if decoder is None:
        raise ValueError("XOR decoder not found")
    strings = []
    seen = set()
    for site in call_sites(text, text_va, decoder["va"]):
        pushed = pushed_string(pe, text, text_va, site)
        if pushed is None or pushed[0] in seen:
            continue
        seen.add(pushed[0])
        raw = read_at(pe, pushed[0], pushed[1])
        value = decode(raw, decoder["key"], decoder["skip"]).decode("latin-1")
        strings.append({"va": hex(pushed[0]), "value": value, "kind": classify(value)})
    strings.sort(key=lambda s: int(s["va"], 16))
    plain_wide = {w.decode("utf-16-le") for w in WIDE.findall(data)}
    otp = [m.group(1).decode("utf-16-le") for m in OTP_LITERAL.finditer(data)]
    hosts = [s["value"] for s in strings if s["kind"] == "host"]
    ports = [s["value"] for s in strings if s["kind"] == "port"]
    paths = [s["value"] for s in strings if s["kind"] == "path"]
    return {
        "sha256": sha256(data),
        "decoder": {
            "va": hex(decoder["va"]),
            "xor_key": hex(decoder["key"]),
            "skip": [hex(b) for b in decoder["skip"]],
        },
        "c2": {
            "host": hosts[0] if hosts else None,
            "port": int(ports[0]) if ports else None,
            "paths": paths,
        },
        "strings": strings,
        "commands": [c for c in COMMANDS if b"\x00" + c.encode() + b"\x00" in data],
        "otp_literals": sorted(set(otp)),
        "client_id_default": "NULL_NULL" if "NULL_NULL" in plain_wide else None,
        "markers": {k: bool(re.search(re.escape(v), data)) for k, v in MARKERS.items()},
    }


def process(path: Path) -> dict:
    data = path.read_bytes()
    record: dict = {"file": str(path), "sha256": sha256(data), "payloads": []}
    payloads = pe_payloads(data)
    if not payloads:
        raise ValueError("no PE found (expected a PE or an MSI with a PE stream)")
    for origin, blob in payloads:
        result = analyse_pe(blob)
        result["origin"] = origin
        record["payloads"].append(result)
    return record


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract the C2 configuration of the C++ PapRAT from its PE or MSI."
    )
    parser.add_argument("files", nargs="+", type=Path, help="PapRAT PE files or MSI installers")
    args = parser.parse_args()
    status = 0
    for path in args.files:
        try:
            record = process(path)
        except Exception as error:
            record = {"file": str(path), "error": str(error)}
            status = 1
        print(json.dumps(record, indent=2))
    return status


if __name__ == "__main__":
    sys.exit(main())
