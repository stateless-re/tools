from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
import zlib
from pathlib import Path

import dnfile
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes

PASSWORD = "{PjlD\\bzxS#;8@\\x.3JT&<4^MsTqE0"
SALT = bytes([34, 65, 11, 12, 16, 0, 65, 128, 92, 72, 65, 23, 87, 11, 10, 8])
ITERATIONS = 192
ICC_TAG = 0x8773
ICC_APP2 = b"ICC_PROFILE\x00"
INTERESTING = re.compile(r"steamcommunity|steamuserimages|pastebin|https?://|\.exe$|^\{.{20,}$")
DESCRIPTION = (
    "SteamHide: read downloader/backdoor settings from a PE, or decrypt the payload "
    "hidden in an image's ICC profile (GDI+ property 0x8773)."
)
NAMED_STRINGS = ("BroMal", "broVPN", "uNoFGmsEX", ".txt", "final.exe", "SquirrelSetup.log")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def derive(password: str, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    base = hashlib.sha512(password.encode() + salt).digest()
    for _ in range(iterations - 2):
        base = hashlib.sha512(base).digest()
    block = hashlib.sha512(base).digest()
    return block[:24], block[24:32]


def decrypt(blob: bytes, password: str, salt: bytes, iterations: int) -> bytes:
    key, iv = derive(password, salt, iterations)
    usable = len(blob) - len(blob) % 8
    decryptor = Cipher(TripleDES(key), modes.CBC(iv)).decryptor()
    plain = decryptor.update(blob[:usable]) + decryptor.finalize()
    unpadder = padding.PKCS7(64).unpadder()
    try:
        return unpadder.update(plain) + unpadder.finalize()
    except ValueError:
        return plain


def jpeg_segments(data: bytes) -> list[tuple[int, bytes]]:
    segments = []
    pos = 2
    while pos + 4 <= len(data) and data[pos] == 0xFF:
        marker = data[pos + 1]
        if marker == 0xD9 or marker == 0xDA:
            break
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        length = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
        segments.append((marker, data[pos + 4 : pos + 2 + length]))
        pos += 2 + length
    return segments


def tiff_tag(tiff: bytes, tag: int) -> bytes | None:
    if tiff[:2] not in (b"II", b"MM"):
        return None
    order = "<" if tiff[:2] == b"II" else ">"
    pending = [struct.unpack(order + "I", tiff[4:8])[0]]
    seen: set[int] = set()
    sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}
    while pending:
        ifd = pending.pop()
        if ifd in seen or ifd + 2 > len(tiff):
            continue
        seen.add(ifd)
        count = struct.unpack(order + "H", tiff[ifd : ifd + 2])[0]
        for index in range(count):
            entry = tiff[ifd + 2 + 12 * index : ifd + 14 + 12 * index]
            if len(entry) < 12:
                break
            entry_tag, kind, number = struct.unpack(order + "HHI", entry[:8])
            size = sizes.get(kind, 1) * number
            value = entry[8:12] if size <= 4 else None
            if value is None:
                offset = struct.unpack(order + "I", entry[8:12])[0]
                value = tiff[offset : offset + size]
            if entry_tag == tag:
                return bytes(value[:size])
            if entry_tag in (0x8769, 0x8825, 0xA005):
                pending.append(struct.unpack(order + "I", entry[8:12])[0])
    return None


def icc_from_jpeg(data: bytes) -> tuple[str, bytes] | None:
    chunks = []
    for marker, body in jpeg_segments(data):
        if marker == 0xE2 and body.startswith(ICC_APP2):
            chunks.append((body[12], body[14:]))
    if chunks:
        return "jpeg-app2-icc", b"".join(part for _, part in sorted(chunks, key=lambda c: c[0]))
    for marker, body in jpeg_segments(data):
        if marker == 0xE1 and body.startswith(b"Exif\x00\x00"):
            value = tiff_tag(body[6:], ICC_TAG)
            if value is not None:
                return "jpeg-exif-0x8773", value
    return None


def icc_from_png(data: bytes) -> tuple[str, bytes] | None:
    pos = 8
    while pos + 8 <= len(data):
        length, kind = struct.unpack(">I4s", data[pos : pos + 8])
        body = data[pos + 8 : pos + 8 + length]
        if kind == b"iCCP":
            name_end = body.index(b"\x00")
            return "png-iccp", zlib.decompress(body[name_end + 2 :])
        pos += 12 + length
    return None


def icc_blob(data: bytes) -> tuple[str, bytes] | None:
    if data[:2] == b"\xff\xd8":
        return icc_from_jpeg(data)
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return icc_from_png(data)
    if data[:4] in (b"II*\x00", b"MM\x00*"):
        value = tiff_tag(data, ICC_TAG)
        return ("tiff-0x8773", value) if value is not None else None
    return None


def user_strings(pe: dnfile.dnPE) -> list[str]:
    heap = pe.net.user_strings.__data__ if pe.net and pe.net.user_strings else b""
    found = []
    pos = 1
    while pos < len(heap):
        first = heap[pos]
        if first & 0x80 == 0:
            size, head = first, 1
        elif first & 0xC0 == 0x80:
            size, head = ((first & 0x3F) << 8) | heap[pos + 1], 2
        else:
            size, head = int.from_bytes(heap[pos : pos + 4], "big") & 0x1FFFFFFF, 4
        if size:
            found.append(heap[pos + head : pos + head + size - 1].decode("utf-16le", "replace"))
        pos += head + size
    return found


def field_rva_blobs(pe: dnfile.dnPE) -> list[bytes]:
    tables = pe.net.mdtables
    if not tables.FieldRva or not tables.ClassLayout:
        return []
    layout = {row.Parent.row_index: row.ClassSize for row in tables.ClassLayout}
    blobs = []
    for row in tables.FieldRva:
        signature = bytes(row.Field.row.Signature.value)
        if len(signature) < 3 or signature[1] != 0x11:
            continue
        coded = signature[2] if signature[2] < 0x80 else ((signature[2] & 0x3F) << 8) | signature[3]
        if coded & 3 != 0:
            continue
        size = layout.get(coded >> 2)
        if size:
            blobs.append(pe.get_data(row.Rva, size))
    return blobs


def describe_pe(path: Path, data: bytes) -> dict:
    pe = dnfile.dnPE(data=data)
    strings = user_strings(pe)
    record: dict = {"file": str(path), "sha256": sha256(data), "kind": "pe"}
    password = next(
        (s for s in strings if s.startswith("{Pjl") or (len(s) == 30 and "\\" in s)), None
    )
    salts = [blob.hex() for blob in field_rva_blobs(pe) if len(blob) == 16]
    record["password"] = password
    record["password_hex"] = password.encode().hex() if password else None
    record["salt_candidates"] = salts
    record["profiles"] = sorted({s for s in strings if "steamcommunity.com/id/" in s})
    record["image_pattern"] = next((s for s in strings if "steamuserimages" in s), None)
    record["pastebin"] = sorted({s for s in strings if "pastebin.com" in s})
    record["names"] = [s for s in NAMED_STRINGS if s in strings]
    record["other_strings"] = [
        s for s in strings if INTERESTING.search(s) and s not in record["profiles"]
    ]
    if password is None:
        record["error"] = "no SteamHide password string found"
    return record


def describe_image(path: Path, data: bytes, args: argparse.Namespace) -> dict:
    record: dict = {"file": str(path), "sha256": sha256(data), "kind": "image"}
    found = ("raw", data) if args.raw else icc_blob(data)
    if found is None:
        record["error"] = "no ICC profile data found"
        return record
    source, blob = found
    record["icc_source"] = source
    record["icc_size"] = len(blob)
    record["icc_looks_genuine"] = len(blob) >= 40 and blob[36:40] == b"acsp"
    plain = decrypt(blob, args.password, bytes.fromhex(args.salt), args.iterations)
    record["decrypted_size"] = len(plain)
    record["decrypted_sha256"] = sha256(plain)
    record["decrypted_is_pe"] = plain[:2] == b"MZ"
    if not record["decrypted_is_pe"]:
        record["error"] = "ICC data does not decrypt to a PE with this key"
        return record
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
        target = args.output / record["decrypted_sha256"]
        target.write_bytes(plain)
        os.chmod(target, 0o600)
        record["written"] = str(target)
    return record


def describe(path: Path, args: argparse.Namespace) -> dict:
    try:
        data = path.read_bytes()
    except OSError as exc:
        return {"file": str(path), "error": f"{type(exc).__name__}: {exc}"}
    try:
        if data[:2] == b"MZ" and not args.raw:
            return describe_pe(path, data)
        return describe_image(path, data, args)
    except Exception as exc:
        return {"file": str(path), "sha256": sha256(data), "error": f"{type(exc).__name__}: {exc}"}


def main() -> int:
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument(
        "-o", "--output", type=Path, help="write decrypted payloads here, named by SHA-256"
    )
    parser.add_argument(
        "--raw", action="store_true", help="treat each input as the bare encrypted ICC blob"
    )
    parser.add_argument("--password", default=PASSWORD)
    parser.add_argument("--salt", default=SALT.hex(), help="hex")
    parser.add_argument("--iterations", type=int, default=ITERATIONS)
    args = parser.parse_args()
    failed = False
    for path in args.files:
        record = describe(path, args)
        failed |= "error" in record
        print(json.dumps(record))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
