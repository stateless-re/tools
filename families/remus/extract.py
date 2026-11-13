import argparse
import hashlib
import json
import re
import struct
import sys
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path

import pefile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

KEY_SETUP_CALLER = re.compile(rb"\x48\x8d\x15(.{4})\x4c\x8d\x05(.{4})", re.DOTALL)
KEY_SIZE = 32
NONCE_SIZE = 8
SLOT_SIZE = 0x40
SLOTS_AFTER_NONCE = 0x10
MAX_SLOTS = 16
TAG_POINTER_OFFSET = 0x10
ETH_CALL = re.compile(r'"to":"(0x[0-9a-fA-F]{40})","data":"(0x[0-9a-fA-F]+)"')
HEX_TAG = re.compile(rb"[0-9a-f]{32}")


class ExtractionError(Exception):
    pass


@dataclass
class Result:
    file: str
    sha256: str
    chacha20_key: str | None = None
    chacha20_nonce: str | None = None
    c2: list[str] = field(default_factory=list)
    rpc_endpoints: list[str] = field(default_factory=list)
    eth_contract: str | None = None
    eth_selector: str | None = None
    tag: str | None = None
    error: str | None = None


def section(pe: pefile.PE, name: bytes) -> pefile.SectionStructure:
    for candidate in pe.sections:
        if candidate.Name.rstrip(b"\0") == name:
            return candidate
    raise ExtractionError(f"no {name.decode()} section")


def chacha20(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    full_nonce = struct.pack("<Q", counter) + nonce
    return Cipher(algorithms.ChaCha20(key, full_nonce), None).decryptor().update(data)


def counter_xor_strings(buffer: bytes, prefix: str, width: int) -> Iterator[str]:
    mask = (1 << (8 * width)) - 1
    unit = "<B" if width == 1 else "<H"
    for offset in range(len(buffer) - width * len(prefix)):

        def unit_at(index: int, start: int = offset) -> int:
            return struct.unpack_from(unit, buffer, start + index * width)[0]

        step = unit_at(0) ^ ord(prefix[0])
        if any(unit_at(i) ^ ((i + 1) * step & mask) != ord(c) for i, c in enumerate(prefix)):
            continue
        chars = []
        for index in range((len(buffer) - offset) // width):
            value = unit_at(index) ^ ((index + 1) * step & mask)
            if value == 0:
                break
            chars.append(chr(value))
        yield "".join(chars)


def c2_slots(pe: pefile.PE, result: Result) -> None:
    text = pe.sections[0]
    rdata = section(pe, b".rdata")
    low = rdata.VirtualAddress
    high = low + rdata.Misc_VirtualSize
    for match in KEY_SETUP_CALLER.finditer(text.get_data()):
        rva = text.VirtualAddress + match.start()
        key_rva = rva + 7 + struct.unpack("<i", match.group(1))[0]
        nonce_rva = rva + 14 + struct.unpack("<i", match.group(2))[0]
        if not low <= key_rva < high or nonce_rva != key_rva + KEY_SIZE:
            continue
        key = pe.get_data(key_rva, KEY_SIZE)
        nonce = pe.get_data(nonce_rva, NONCE_SIZE)
        urls = []
        for slot in range(MAX_SLOTS):
            ciphertext = pe.get_data(nonce_rva + SLOTS_AFTER_NONCE + slot * SLOT_SIZE, SLOT_SIZE)
            plaintext = chacha20(key, nonce, slot, ciphertext)
            if not plaintext.startswith(b"http"):
                break
            urls.append(plaintext.split(b"\0")[0].decode())
        if urls:
            result.chacha20_key = key.hex()
            result.chacha20_nonce = nonce.hex()
            result.c2 = urls
            return
    raise ExtractionError("ChaCha20 C2 slots not found")


def ethereum_fallback(pe: pefile.PE, result: Result) -> None:
    rdata = section(pe, b".rdata").get_data()
    result.rpc_endpoints = sorted(set(counter_xor_strings(rdata, "https://", 2)))
    for body in counter_xor_strings(rdata, '{"jsonrpc"', 1):
        match = ETH_CALL.search(body)
        if match:
            result.eth_contract, result.eth_selector = match.groups()


def build_tag(pe: pefile.PE, result: Result) -> None:
    data = section(pe, b".data").get_data()
    pointer = struct.unpack_from("<Q", data, TAG_POINTER_OFFSET)[0]
    rva = pointer - pe.OPTIONAL_HEADER.ImageBase
    if 0 < rva < pe.OPTIONAL_HEADER.SizeOfImage:
        value = pe.get_data(rva, 64).split(b"\0")[0]
        if HEX_TAG.fullmatch(value):
            result.tag = value.decode()


def extract(path: Path) -> Result:
    raw = path.read_bytes()
    result = Result(file=str(path), sha256=hashlib.sha256(raw).hexdigest())
    pe = pefile.PE(data=raw, fast_load=True)
    c2_slots(pe, result)
    ethereum_fallback(pe, result)
    build_tag(pe, result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract C2 slots, Ethereum fallback and build tag from Remus x64 payloads."
    )
    parser.add_argument("files", nargs="+", type=Path)
    args = parser.parse_args()
    results = []
    failed = False
    for path in args.files:
        try:
            results.append(extract(path))
        except (OSError, pefile.PEFormatError, ExtractionError) as error:
            failed = True
            results.append(Result(file=str(path), sha256="", error=str(error)))
    print(json.dumps([asdict(r) for r in results], indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
