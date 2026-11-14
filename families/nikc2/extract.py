import argparse
import base64
import gzip
import hashlib
import json
import os
import re
import struct
import sys
import zlib
from dataclasses import dataclass, field

import pefile
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

FCX_MASTER_KEY = base64.b64decode("4jVQKrMrgKNliQB/VbybdDhEiC2vcegq9X+v7NVqZSk=")
PYINSTALLER_COOKIE = b"MEI\x0c\x0b\x0a\x0b\x0e"
HEX_STRING = re.compile(rb"[0-9a-f]+")
WRAPPED_FIELD = re.compile(rb"[A-Za-z0-9+/=]{40,}\|[A-Za-z0-9+/=]{20,}\|[A-Za-z0-9+/=]+")
IV_FIELD = re.compile(rb"[A-Za-z0-9+/=]{24}:[A-Za-z0-9+/=]+")
EMBEDDED_PE_B64 = re.compile(rb"TVqQAAMAAAAEAAAA//8AA[A-Za-z0-9+/]{1000,}={0,2}")
IP_URL = re.compile(rb"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}")
BUILD_PATH = re.compile(rb"/opt/nik_panel/data/build_[0-9a-f]{16}")
GO_VERSION = re.compile(rb"go1\.\d+\.\d+")
DEC_CALL = re.compile(rb"\x48\x8b\x05(.{4})\x48\x8b\x1d(.{4})\xe8(.{4})(\x48\x89\x1d(.{4}))?", re.S)
PCLNTAB_MAGIC = b"\xf1\xff\xff\xff\x00\x00\x01\x08"
SLOT_NAMES_V1 = {
    0x10: "user_uid",
    0x20: "hide_console",
    0x30: "seed",
    0x40: "agent_id",
    0x50: "watchdog",
    0x60: "masquerade",
    0x70: "autostart",
    0x80: "install",
    0x90: "cleanup_original",
    0xA0: "process_name",
    0xB0: "self_heal",
}


@dataclass
class Image:
    pe: pefile.PE
    base: int
    mapped: bytes
    data_start: int
    data_end: int

    def read(self, va: int, size: int) -> bytes:
        offset = va - self.base
        if offset < 0 or offset + size > len(self.mapped):
            return b""
        return self.mapped[offset : offset + size]

    def string_at(self, va: int) -> bytes | None:
        header = self.read(va, 16)
        if len(header) < 16:
            return None
        pointer, length = struct.unpack("<QQ", header)
        if length == 0 or length > 0x100000:
            return None
        return self.read(pointer, length) or None


@dataclass
class Result:
    file: str
    sha256: str
    wrappers: list[dict] = field(default_factory=list)
    agents: list[dict] = field(default_factory=list)
    error: str | None = None


def rolling_xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ ((key[i % 3] + i) & 0xFF) for i, b in enumerate(data))


def derive_xor_key(cipher: bytes, prefix: bytes = b"https://") -> bytes | None:
    if len(cipher) < len(prefix):
        return None
    key = bytes(((cipher[i] ^ prefix[i]) - i) & 0xFF for i in range(3))
    if rolling_xor(cipher[: len(prefix)], key) == prefix:
        return key
    return None


def decode_hex_field(value: bytes, key: bytes) -> str | None:
    if not HEX_STRING.fullmatch(value) or len(value) % 2:
        return None
    return rolling_xor(bytes.fromhex(value.decode()), key).decode("latin1")


def load_image(data: bytes) -> Image:
    pe = pefile.PE(data=data, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    section = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".data")
    start = base + section.VirtualAddress
    return Image(pe, base, pe.get_memory_mapped_image(), start, start + section.Misc_VirtualSize)


def string_headers(image: Image) -> list[tuple[int, bytes]]:
    headers = []
    raw = image.read(image.data_start, image.data_end - image.data_start)
    for offset in range(0, len(raw) - 16, 8):
        pointer, length = struct.unpack_from("<QQ", raw, offset)
        if 0 < length < 0x4000 and image.base <= pointer < image.base + len(image.mapped):
            value = image.read(pointer, length)
            if value:
                headers.append((image.data_start + offset, value))
    return headers


def find_c2_slot(headers: list[tuple[int, bytes]]) -> tuple[int, str, bytes | None] | None:
    for address, value in headers:
        if HEX_STRING.fullmatch(value) and len(value) % 2 == 0 and len(value) >= 16:
            cipher = bytes.fromhex(value[:16].decode())
            for prefix in (b"https://", b"http://"):
                key = derive_xor_key(cipher, prefix)
                if key:
                    return address, "v1", key
    for address, value in headers:
        if WRAPPED_FIELD.fullmatch(value):
            return address, "v2", None
    return None


def describe_wrapped(value: bytes) -> dict:
    if WRAPPED_FIELD.fullmatch(value):
        parts = [base64.b64decode(p) for p in value.split(b"|")]
        return {
            "scheme": "wrapped_key|iv|ciphertext",
            "wrapped_key_bytes": len(parts[0]),
            "iv_bytes": len(parts[1]),
            "ciphertext_bytes": len(parts[2]),
        }
    if IV_FIELD.fullmatch(value):
        iv, cipher = (base64.b64decode(p) for p in value.split(b":"))
        return {"scheme": "iv:ciphertext", "iv_bytes": len(iv), "ciphertext_bytes": len(cipher)}
    return {"scheme": "unknown", "length": len(value)}


def read_slots(image: Image, start: int) -> dict[int, bytes]:
    slots = {}
    misses = 0
    for offset in range(0, 0x200, 0x10):
        value = image.string_at(start + offset)
        if value is None:
            misses += 1
            if misses >= 2:
                break
            continue
        misses = 0
        slots[offset] = value
    return slots


def classify_slots(slots: dict[int, bytes], fmt: str, key: bytes | None) -> dict:
    config: dict = {}
    extra: dict = {}
    for offset, value in sorted(slots.items()):
        text = value.decode("latin1")
        if offset == 0:
            config["c2"] = decode_hex_field(value, key) if key else describe_wrapped(value)
        elif offset in (0x10, 0x30, 0x40):
            name = SLOT_NAMES_V1[offset]
            config[name] = decode_hex_field(value, key) if key else describe_wrapped(value)
        elif re.fullmatch(r"[0-9a-f]{64}", text) and "cert_pin_sha256" not in config:
            config["cert_pin_sha256"] = text
            config["cert_pin_slot"] = hex(offset)
        elif text.lower().endswith(".exe") and "process_name" not in config:
            config["process_name"] = text
        elif text in ("true", "false"):
            name = SLOT_NAMES_V1.get(offset) if offset != 0xA0 else None
            extra[name or f"flag_{offset:#05x}"] = text == "true"
        elif fmt == "v2" and (WRAPPED_FIELD.fullmatch(value) or IV_FIELD.fullmatch(value)):
            extra[f"protected_{offset:#05x}"] = describe_wrapped(value)
        else:
            extra[f"slot_{offset:#05x}"] = text
    if fmt == "v1" and isinstance(config.get("seed"), str):
        config["aes_key"] = hashlib.sha256(config["seed"].encode()).hexdigest()
    config["flags"] = extra
    return config


def rip_target(image: Image, file_offset: int, disp: bytes, length: int) -> int:
    rva = image.pe.get_rva_from_offset(file_offset)
    return image.base + rva + length + struct.unpack("<i", disp)[0]


def find_server_lists(image: Image, raw: bytes, c2_slot: int, slots: dict, key: bytes | None):
    calls = []
    for match in DEC_CALL.finditer(raw):
        start = match.start()
        if image.pe.get_rva_from_offset(start) is None:
            continue
        first = rip_target(image, start, match.group(1), 7)
        second = rip_target(image, start + 7, match.group(2), 7)
        target = rip_target(image, start + 14, match.group(3), 5)
        stored = match.group(5) and rip_target(image, start + 19, match.group(5), 7)
        if second == first + 8:
            calls.append((first, target, stored == first + 8))
    decoders = {target for first, target, in_place in calls if first == c2_slot and in_place}
    if not decoders:
        return None
    lists = []
    seen = set()
    for first, target, in_place in calls:
        if target in decoders and not in_place and first not in seen:
            seen.add(first)
            value = image.string_at(first)
            entry = {"global": hex(first), "encoded_length": len(value) if value else 0}
            if value and key:
                decoded = decode_hex_field(value, key)
                entry["servers"] = [s.strip() for s in (decoded or "").split("|") if s.strip()]
            elif value:
                entry["protected"] = describe_wrapped(value)
            else:
                entry["servers"] = []
            lists.append(entry)
    return lists


def go_functions(image: Image, raw: bytes) -> list[str]:
    index = raw.find(PCLNTAB_MAGIC)
    if index < 0:
        return []
    table = raw[index:]
    nfunc = struct.unpack_from("<Q", table, 8)[0]
    name_offset = struct.unpack_from("<Q", table, 32)[0]
    pcln_offset = struct.unpack_from("<Q", table, 64)[0]
    names = []
    for i in range(nfunc):
        func_offset = struct.unpack_from("<I", table, pcln_offset + i * 8 + 4)[0]
        name_ref = struct.unpack_from("<i", table, pcln_offset + func_offset + 4)[0]
        start = name_offset + name_ref
        names.append(table[start : table.index(b"\0", start)].decode("latin1"))
    return names


def parse_agent(data: bytes) -> dict:
    image = load_image(data)
    headers = string_headers(image)
    found = find_c2_slot(headers)
    if not found:
        raise ValueError("no NIK C2 config slot found")
    c2_slot, fmt, key = found
    slots = read_slots(image, c2_slot)
    config = classify_slots(slots, fmt, key)
    functions = go_functions(image, data)
    handlers = sorted(
        n[len("main.handle") :] for n in functions if re.fullmatch(r"main\.handle\w+", n)
    )
    build_path = BUILD_PATH.search(data)
    go_version = GO_VERSION.search(data)
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "format": fmt,
        "xor_key": key.hex() if key else None,
        "config_slot": hex(c2_slot),
        "config": config,
        "server_lists": find_server_lists(image, data, c2_slot, slots, key),
        "fallback_urls": sorted({m.decode() for m in IP_URL.findall(data)}),
        "build_path": build_path.group().decode() if build_path else None,
        "go_version": go_version.group().decode() if go_version else None,
        "symbols": bool(functions),
        "handler_count": len(handlers) if functions else None,
        "handlers": handlers if functions else None,
    }


def hkdf_key(salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(FCX_MASTER_KEY)


def unwrap_fcx(data: bytes) -> tuple[dict, bytes] | None:
    if data[-4:] != b"FCX1":
        return None
    size = struct.unpack_from("<I", data, len(data) - 8)[0]
    blob = data[len(data) - 8 - size : len(data) - 8]
    if blob[:4] != b"SX11":
        return None
    salt, aes_nonce, chacha_nonce = blob[4:20], blob[20:32], blob[32:44]
    length = struct.unpack_from("<i", blob, 44)[0]
    aad = b"SX11" + salt
    inner = ChaCha20Poly1305(hkdf_key(salt, b"SX11-CHACHA20-POLY1305")).decrypt(
        chacha_nonce, blob[48 : 48 + length], aad
    )
    plain = AESGCM(hkdf_key(salt, b"SX11-AES-256-GCM")).decrypt(aes_nonce, inner, aad)
    name_length = struct.unpack_from("<i", plain, 1)[0]
    name = plain[5 : 5 + name_length].decode("utf-8", "replace")
    payload_length = struct.unpack_from("<i", plain, 5 + name_length)[0]
    payload = plain[9 + name_length : 9 + name_length + payload_length]
    if plain[0] == 1:
        payload = gzip.decompress(payload)
    info = {
        "type": "FileCrypt FCX1/SX11",
        "offset": hex(len(data) - 8 - size),
        "inner_name": name,
        "inner_sha256": hashlib.sha256(payload).hexdigest(),
    }
    return info, payload


def unwrap_pyinstaller(data: bytes) -> tuple[dict, list[bytes]] | None:
    cookie = data.rfind(PYINSTALLER_COOKIE)
    if cookie < 0:
        return None
    package_length, toc, toc_length = struct.unpack_from("!III", data, cookie + 8)
    package = cookie + 88 - package_length
    position, end = package + toc, package + toc + toc_length
    payloads = []
    scripts = []
    while position < end:
        entry_length, offset, compressed, _, flag, kind = struct.unpack_from(
            "!IIIIBc", data, position
        )
        name = data[position + 18 : position + entry_length].rstrip(b"\0").decode("latin1")
        position += entry_length
        if kind != b"s" or name.startswith("pyi"):
            continue
        body = data[package + offset : package + offset + compressed]
        code = zlib.decompress(body) if flag else body
        scripts.append(name)
        payloads.extend(base64.b64decode(m.group()) for m in EMBEDDED_PE_B64.finditer(code))
    info = {
        "type": "PyInstaller binder",
        "scripts": scripts,
        "embedded_pe_sha256": [hashlib.sha256(p).hexdigest() for p in payloads],
    }
    return info, payloads


def is_go_agent(data: bytes) -> bool:
    return data[:2] == b"MZ" and b"/api/c2/update" in data


def save(payload: bytes, directory: str) -> None:
    path = os.path.join(directory, hashlib.sha256(payload).hexdigest() + ".bin")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)


def process(data: bytes, result: Result, out_dir: str | None, depth: int = 0) -> None:
    if depth > 3:
        return
    fcx = unwrap_fcx(data)
    if fcx:
        result.wrappers.append(fcx[0])
        if out_dir:
            save(fcx[1], out_dir)
        process(fcx[1], result, out_dir, depth + 1)
        return
    binder = unwrap_pyinstaller(data)
    if binder:
        result.wrappers.append(binder[0])
        for payload in binder[1]:
            if out_dir:
                save(payload, out_dir)
            process(payload, result, out_dir, depth + 1)
        return
    if is_go_agent(data):
        result.agents.append(parse_agent(data))


def run(path: str, out_dir: str | None) -> Result:
    with open(path, "rb") as handle:
        data = handle.read()
    result = Result(os.path.basename(path), hashlib.sha256(data).hexdigest())
    try:
        process(data, result, out_dir)
        if not result.agents:
            result.error = "no NIK C2 agent found"
    except (ValueError, pefile.PEFormatError, struct.error, zlib.error, StopIteration) as exc:
        result.error = f"{type(exc).__name__}: {exc}"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract NIK C2 (NIKRAT) agent configs from agents, FileCrypt-packed files "
        "and PyInstaller binders. Static only."
    )
    parser.add_argument("files", nargs="+", help="samples to parse")
    parser.add_argument("-o", "--out-dir", help="write unwrapped inner PEs here (mode 600)")
    parser.add_argument("--no-handlers", action="store_true", help="omit the handler name list")
    args = parser.parse_args()
    results = [run(path, args.out_dir) for path in args.files]
    if args.no_handlers:
        for result in results:
            for agent in result.agents:
                agent.pop("handlers", None)
    json.dump([vars(r) for r in results], sys.stdout, indent=2)
    print()
    return 1 if any(r.error for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
