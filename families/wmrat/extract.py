import argparse
import hashlib
import json
import re
import struct
import sys
from collections.abc import Callable
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

CANDIDATE = re.compile(rb"[\x21-\xfe]{6,80}\x00")
DOMAIN = re.compile(rb"[a-z0-9][a-z0-9-]{2,62}(\.[a-z0-9-]{2,62})*\.[a-z]{2,12}")
IPV4 = re.compile(rb"\d{1,3}(\.\d{1,3}){3}")
HTONS_ORDINAL = 9


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def flat(key: int) -> Callable[[bytes], bytes]:
    return lambda blob: bytes((b - key) & 0xFF for b in blob)


def positional(key: int) -> Callable[[bytes], bytes]:
    return lambda blob: bytes((b - min(i - 1, 10) - key) & 0xFF for i, b in enumerate(blob))


def xor_index_then_sub(key: int) -> Callable[[bytes], bytes]:
    return lambda blob: bytes(((b ^ (i & 0xFF)) - key) & 0xFF for i, b in enumerate(blob))


TRANSFORMS: dict[str, Callable[[int], Callable[[bytes], bytes]]] = {
    "sub": flat,
    "sub_position": positional,
    "xor_index_sub": xor_index_then_sub,
}


def describe(name: str, key: int) -> str:
    if name == "sub":
        return f"out[i] = in[i] - {key:#x}"
    if name == "sub_position":
        return f"out[i] = in[i] - min(i - 1, 10) - {key:#x}"
    return f"out[i] = (in[i] ^ i) - {key:#x}"


def rdata(pe: pefile.PE) -> tuple[bytes, int]:
    for section in pe.sections:
        if section.Name.rstrip(b"\x00") == b".rdata":
            return section.get_data(), pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
    raise ValueError("no .rdata section")


def find_c2(pe: pefile.PE) -> list[dict]:
    data, base = rdata(pe)
    hits = []
    for match in CANDIDATE.finditer(data):
        blob = match.group()[:-1]
        if DOMAIN.fullmatch(blob) or IPV4.fullmatch(blob):
            continue
        for name, factory in TRANSFORMS.items():
            for key in range(1, 0x100):
                plain = factory(key)(blob)
                if DOMAIN.fullmatch(plain) or IPV4.fullmatch(plain):
                    hits.append(
                        {
                            "va": hex(base + match.start()),
                            "c2": plain.decode(),
                            "transform": name,
                            "key": key,
                            "formula": describe(name, key),
                        }
                    )
    return hits


def decode_all(pe: pefile.PE, name: str, key: int) -> list[dict]:
    data, base = rdata(pe)
    out = []
    transform = TRANSFORMS[name](key)
    for match in CANDIDATE.finditer(data):
        plain = transform(match.group()[:-1])
        if all(0x20 <= b < 0x7F for b in plain) and re.search(rb"[A-Za-z]{3}", plain):
            out.append({"va": hex(base + match.start()), "value": plain.decode()})
    return out


def htons_iat(pe: pefile.PE) -> int | None:
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        if not entry.dll.lower().startswith(b"ws2_32"):
            continue
        for item in entry.imports:
            if item.ordinal == HTONS_ORDINAL or item.name == b"htons":
                return item.address
    return None


def find_ports(pe: pefile.PE) -> list[int]:
    iat = htons_iat(pe)
    if iat is None:
        return []
    base = pe.OPTIONAL_HEADER.ImageBase
    text = next(s for s in pe.sections if s.Name.startswith(b".text"))
    code = text.get_data()
    text_va = base + text.VirtualAddress
    disasm = Cs(CS_ARCH_X86, CS_MODE_32)
    disasm.detail = True
    pattern = b"\xff\x15" + struct.pack("<I", iat)
    ports = []
    offset = code.find(pattern)
    while offset >= 0:
        window = list(
            disasm.disasm(code[max(0, offset - 24) : offset], text_va + max(0, offset - 24))
        )
        port = port_from_window(pe, window)
        if port:
            ports.append(port)
        offset = code.find(pattern, offset + 1)
    return sorted(set(ports))


def port_from_window(pe: pefile.PE, window: list) -> int | None:
    base = pe.OPTIONAL_HEADER.ImageBase
    for instruction in reversed(window):
        if instruction.mnemonic == "push" and instruction.operands[0].type == X86_OP_IMM:
            value = instruction.operands[0].imm & 0xFFFFFFFF
            return value if 0 < value < 0x10000 else None
        if instruction.mnemonic == "movzx" and instruction.operands[1].type == X86_OP_MEM:
            address = instruction.operands[1].mem.disp & 0xFFFFFFFF
            if instruction.operands[1].mem.base == 0 and address > base:
                return struct.unpack("<H", pe.get_data(address - base, 2))[0]
    return None


def process(path: Path, strings: bool) -> dict:
    data = path.read_bytes()
    pe = pefile.PE(data=data)
    hits = find_c2(pe)
    if not hits:
        raise ValueError("no C2 decoded with the known string transforms")
    record = {
        "file": str(path),
        "sha256": sha256(data),
        "compiled": pe.FILE_HEADER.TimeDateStamp,
        "c2": hits,
        "ports": find_ports(pe),
    }
    if strings:
        record["strings"] = decode_all(pe, hits[0]["transform"], hits[0]["key"])
    return record


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decode the C2 host, port and string transform of BITTER's WmRAT builds."
    )
    parser.add_argument("files", nargs="+", type=Path, help="WmRAT PE files")
    parser.add_argument("--strings", action="store_true", help="also decode every .rdata string")
    args = parser.parse_args()
    status = 0
    for path in args.files:
        try:
            record = process(path, args.strings)
        except Exception as error:
            record = {"file": str(path), "error": str(error)}
            status = 1
        print(json.dumps(record, indent=2))
    return status


if __name__ == "__main__":
    sys.exit(main())
