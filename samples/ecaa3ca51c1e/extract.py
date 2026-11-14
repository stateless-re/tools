import argparse
import base64
import hashlib
import io
import json
import os
import re
import struct
import sys
import zipfile
from pathlib import Path

import dnfile
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

FNV_MASK = 0xC6E39BD8
LFSR_SEED = 0x95000000
LFSR_TAPS = 0x60000
DEFAULT_TOKEN = "1e627e8ceed85007"
PARAM_NAMES = ["ver", "chan", "lang", "arch", "build"]
PARAM_WIDTHS = [4, 3, 3, 3, 3]
MASK_GROUPS = {
    0: "Norton",
    2: "Bitdefender, Ad-Aware, Emsisoft, F-Secure, G DATA, Tencent",
    5: "Webroot",
    6: "Malwarebytes",
    7: "Microsoft Defender",
    8: "McAfee",
    9: "unresolved table uint_13",
    10: "Avast, AVG",
    11: "unresolved table uint_3",
    12: "Python",
}
LEN_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99]
LEN_BASE += [115, 131, 163, 195, 227, 258]
LEN_EXTRA = [0] * 8 + [i // 4 for i in range(4, 24)] + [0]
DIST_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025]
DIST_BASE += [1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577]
DIST_EXTRA = [0, 0, 0, 0] + [i // 2 - 1 for i in range(4, 30)]
CL_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]


class BitReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0
        self.buf = 0
        self.count = 0

    def bits(self, n: int) -> int:
        while self.count < n:
            self.buf |= self.data[self.pos] << self.count
            self.pos += 1
            self.count += 8
        value = self.buf & ((1 << n) - 1)
        self.buf >>= n
        self.count -= n
        return value

    def align(self) -> None:
        self.buf = 0
        self.count = 0


def huffman_table(lengths: list[int]) -> dict[tuple[int, int], int]:
    counts = [0] * 16
    for length in lengths:
        if length:
            counts[length] += 1
    next_code = [0] * 16
    code = 0
    for bits in range(1, 16):
        code = (code + counts[bits - 1]) << 1
        next_code[bits] = code
    table = {}
    for symbol, length in enumerate(lengths):
        if length:
            table[(length, next_code[length])] = symbol
            next_code[length] += 1
    return table


def read_symbol(reader: BitReader, table: dict[tuple[int, int], int]) -> int:
    code = 0
    for length in range(1, 16):
        code = (code << 1) | reader.bits(1)
        if (length, code) in table:
            return table[(length, code)]
    raise ValueError("invalid huffman code")


FIXED_LIT = huffman_table([8] * 144 + [9] * 112 + [7] * 24 + [8] * 8)
FIXED_DIST = huffman_table([5] * 30)


def dynamic_tables(reader: BitReader) -> tuple[dict, dict]:
    hlit = reader.bits(5) + 257
    hdist = reader.bits(5) + 1
    hclen = reader.bits(4) + 4
    cl = [0] * 19
    for i in range(hclen):
        cl[CL_ORDER[i]] = reader.bits(3)
    cl_table = huffman_table(cl)
    lengths: list[int] = []
    while len(lengths) < hlit + hdist:
        sym = read_symbol(reader, cl_table)
        if sym < 16:
            lengths.append(sym)
        elif sym == 16:
            lengths += [lengths[-1]] * (3 + reader.bits(2))
        elif sym == 17:
            lengths += [0] * (3 + reader.bits(3))
        else:
            lengths += [0] * (11 + reader.bits(7))
    return huffman_table(lengths[:hlit]), huffman_table(lengths[hlit:])


def inflate_variant(data: bytes, magic: int) -> bytes:
    reader = BitReader(data)
    out = bytearray()
    while True:
        final = reader.bits(1)
        kind = reader.bits(3)
        if kind == 3:
            reader.align()
            size = reader.bits(16) ^ magic
            out += data[reader.pos : reader.pos + size]
            reader.pos += size
        elif kind in (2, 4):
            lit, dist = (FIXED_LIT, FIXED_DIST) if kind == 2 else dynamic_tables(reader)
            while True:
                sym = read_symbol(reader, lit)
                if sym < 256:
                    out.append(sym)
                    continue
                if sym == 256:
                    break
                sym -= 257
                length = LEN_BASE[sym] + reader.bits(LEN_EXTRA[sym])
                dsym = read_symbol(reader, dist)
                distance = DIST_BASE[dsym] + reader.bits(DIST_EXTRA[dsym])
                for _ in range(length):
                    out.append(out[-distance])
        else:
            raise ValueError(f"unknown block type {kind}")
        if final:
            return bytes(out)


def read_7bit_string(stream: io.BytesIO) -> str:
    size = shift = 0
    while True:
        byte = stream.read(1)[0]
        size |= (byte & 0x7F) << shift
        shift += 7
        if byte < 0x80:
            break
    return stream.read(size).decode("utf-8")


def parse_protected_resource(blob: bytes, magic: int) -> tuple[dict, bytes]:
    header_len = struct.unpack_from("<H", blob, 0)[0]
    header = bytearray(blob[2 : 2 + header_len])
    xor_key = blob[2 + header_len : 6 + header_len]
    for i in range(header_len):
        header[i] ^= xor_key[i % 4]
    stream = io.BytesIO(bytes(header))
    tag = read_7bit_string(stream)
    encrypted, compressed = stream.read(1)[0], stream.read(1)[0]
    stream.read(struct.unpack("<i", stream.read(4))[0])
    stream.read(1)
    key = stream.read(stream.read(1)[0])
    iv = stream.read(stream.read(1)[0])
    body = blob[6 + header_len :]
    if encrypted:
        decryptor = Cipher(TripleDES(key * 3), modes.CBC(iv)).decryptor()
        body = decryptor.update(body) + decryptor.finalize()
        body = body[: -body[-1]]
    if compressed:
        body = inflate_variant(body, magic)
    info = {"tag": tag, "des_key": key.hex(), "des_iv": iv.hex(), "header_xor": xor_key.hex()}
    return info, body


def find_id_key(pe: dnfile.dnPE) -> int | None:
    heap = pe.net.user_strings
    if heap is None:
        return None
    for match in re.finditer(rb"((?:[A-Za-z0-9+/]\x00){40,}(?:=\x00){0,2})", heap.__data__):
        text = match.group(1).decode("utf-16-le")
        try:
            decoded = base64.b64decode(text)
        except ValueError:
            continue
        found = re.search(rb";SetData;(\d+);", decoded)
        if found:
            return int(found.group(1))
    return None


def resource_strings(body: bytes, id_key: int | None, id_add: int) -> list[dict]:
    stream = io.BytesIO(body)
    items = []
    while stream.tell() < len(body):
        offset = stream.tell()
        value = read_7bit_string(stream)
        item: dict = {"offset": offset, "value": value}
        if id_key is not None:
            item["id"] = (offset + id_add) ^ id_key
        items.append(item)
    return items


def type_sizes(pe: dnfile.dnPE) -> dict[int, int]:
    return {row.Parent.row_index: row.ClassSize for row in pe.net.mdtables.ClassLayout}


def field_blobs(pe: dnfile.dnPE) -> list[tuple[int, bytes]]:
    sizes = type_sizes(pe)
    blobs = []
    for row in pe.net.mdtables.FieldRva:
        sig = bytes(row.Field.row.Signature.value)
        if len(sig) < 3 or sig[1] != 0x11:
            continue
        coded = sig[2]
        if coded & 0x80:
            coded = ((coded & 0x3F) << 8) | sig[3]
        if coded & 3 != 0:
            continue
        size = sizes.get(coded >> 2)
        if not size:
            continue
        offset = pe.get_offset_from_rva(row.Rva)
        blobs.append((row.Rva, pe.__data__[offset : offset + size]))
    return blobs


def xor_string(blob: bytes) -> str:
    return "".join(chr(b ^ ((i * 37 + 107) & 0xFF)) for i, b in enumerate(blob))


def printable(text: str) -> bool:
    return len(text) >= 2 and all(32 <= ord(c) < 127 for c in text)


def fnv1a_lower(name: str) -> int:
    value = 0x811C9DC5
    for char in name:
        code = ord(char)
        if 65 <= code <= 90:
            code += 32
        value = ((value ^ code) * 0x01000193) & 0xFFFFFFFF
    return value


def hash_matches(blobs: list[tuple[int, bytes]], names: list[str]) -> list[dict]:
    lookup: dict[int, set[str]] = {}
    for name in names:
        for variant in {name, name + ".exe"} if "." not in name else {name}:
            lookup.setdefault(fnv1a_lower(variant), set()).add(variant.lower())
    found = []
    for rva, blob in blobs:
        if len(blob) % 4:
            continue
        values = [v ^ FNV_MASK for v in struct.unpack(f"<{len(blob) // 4}I", blob)]
        hits = sorted({n for v in values for n in lookup.get(v, ())})
        if hits:
            found.append({"rva": hex(rva), "entries": len(values), "matches": hits})
    return found


def build_urls(host: str, extra: str, tokens: list[str]) -> list[dict]:
    urls = []
    for token in tokens:
        parts, pos = [], 0
        for name, width in zip(PARAM_NAMES, PARAM_WIDTHS, strict=True):
            parts.append(f"{name}={token[pos : pos + width]}")
            pos += width
        urls.append({"token": token, "url": f"https://{host}/?{'&'.join(parts)}{extra}"})
    return urls


def lfsr_xor(data: bytearray) -> None:
    state = LFSR_SEED
    for i in range(len(data) * 8):
        tapped = state & LFSR_TAPS
        feedback = bin(tapped).count("1") & 1
        state >>= 1
        if feedback:
            state |= 0x80000000
        if feedback:
            data[i >> 3] ^= 1 << (7 - (i & 7))


def decrypt_blob(blob: bytes) -> bytes:
    if len(blob) <= 4 or struct.unpack_from("<I", blob, len(blob) - 4)[0] + 4 != len(blob):
        raise ValueError("length trailer does not match")
    quarter = len(blob) // 4
    if quarter < 65536:
        raise ValueError("blob too small")
    work = bytearray(quarter)
    work[64:] = blob[32 : 32 + quarter - 64]
    lfsr_xor(work)
    size = struct.unpack_from("<I", work, 64)[0]
    if not 65536 < size < quarter - 68:
        raise ValueError(f"bad inner size {size}")
    return bytes(work[68 : 68 + size])


def decode_uid(uid: str, token: str) -> dict:
    nibbles = [int(uid[4 + i], 16) ^ int(token[i], 16) ^ int(token[i + 7], 16) for i in range(4)]
    weight_hex = "".join(f"{n ^ int(uid[i], 16):x}" for i, n in enumerate(nibbles))
    weight = int(weight_hex, 16)
    bits = [k for k in range(14) if weight & (0x8000 >> k)]
    return {
        "uid": uid,
        "mask_weight": weight_hex,
        "bits": bits,
        "products": [MASK_GROUPS.get(k, f"bit {k}") for k in bits],
    }


def manifest_resources(pe: dnfile.dnPE) -> list[tuple[str, bytes]]:
    out = []
    for res in pe.net.resources or []:
        if isinstance(res.data, bytes | bytearray):
            out.append((str(res.name), bytes(res.data)))
    return out


def describe_child(name: str, data: bytes) -> dict:
    entry: dict = {"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    if data[:2] == b"MZ":
        entry["kind"] = "pe"
    elif data[:4] == b"PK\x03\x04":
        entry["kind"] = "zip"
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entry["entries"] = [
                {
                    "name": info.filename,
                    "size": info.file_size,
                    "sha256": hashlib.sha256(archive.read(info)).hexdigest(),
                }
                for info in archive.infolist()
            ]
    return entry


def analyze(path: Path, args: argparse.Namespace) -> dict:
    data = path.read_bytes()
    pe = dnfile.dnPE(data=data)
    record: dict = {"file": str(path), "sha256": hashlib.sha256(data).hexdigest()}
    blobs = field_blobs(pe)
    record["xor_strings"] = [s for _, b in blobs if printable(s := xor_string(b))]
    children, store = [], None
    for name, blob in manifest_resources(pe):
        try:
            info, body = parse_protected_resource(blob, args.magic)
            store = {"resource": name, **info}
            strings = resource_strings(body, find_id_key(pe), args.id_add)
        except (ValueError, IndexError, UnicodeDecodeError, struct.error):
            children.append(describe_child(name, blob))
    record["children"] = children
    if store:
        values = [s["value"] for s in strings]
        record["string_store"] = store
        record["resource_strings"] = strings
        host = next((values[i + 1] for i, v in enumerate(values[:-1]) if v == "https://"), None)
        extra = next((v for v in values if re.fullmatch(r"&\w+=\w+", v)), "")
        tokens = [v for v in values if re.fullmatch(r"[0-9a-f]{16}", v) and v != "0123456789abcdef"]
        if host:
            record["urls"] = build_urls(host, extra, tokens)
    if args.names:
        names = [n.strip() for n in args.names.read_text().splitlines() if n.strip()]
        record["hash_tables"] = hash_matches(blobs, names)
    return record


def write_payload(directory: Path, payload: bytes) -> str:
    digest = hashlib.sha256(payload).hexdigest()
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / digest
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
    return str(target)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Static extractor for the FrauPDF installer (ecaa3ca51c1e...)"
    )
    parser.add_argument("files", nargs="*", type=Path, help="installer executables")
    parser.add_argument("--magic", type=lambda v: int(v, 0), default=0xF112)
    parser.add_argument("--id-add", type=int, default=22)
    parser.add_argument("--names", type=Path, help="name list to match against hash tables")
    parser.add_argument("--blob", type=Path, action="append", default=[], help="server blob")
    parser.add_argument("--uid", action="append", default=[], help="uid query value")
    parser.add_argument("--token", default=DEFAULT_TOKEN)
    parser.add_argument("-o", "--output", type=Path, help="write decrypted stages here")
    args = parser.parse_args()
    failed = False
    for path in args.files:
        try:
            record = analyze(path, args)
        except Exception as exc:
            record, failed = {"file": str(path), "error": str(exc)}, True
        print(json.dumps(record, indent=1, ensure_ascii=False))
    for path in args.blob:
        try:
            stage = decrypt_blob(path.read_bytes())
            record = {"blob": str(path), "stage_sha256": hashlib.sha256(stage).hexdigest()}
            record["stage_size"] = len(stage)
            if args.output:
                record["written"] = write_payload(args.output, stage)
        except Exception as exc:
            record, failed = {"blob": str(path), "error": str(exc)}, True
        print(json.dumps(record, indent=1))
    for uid in args.uid:
        try:
            record = decode_uid(uid, args.token)
        except Exception as exc:
            record, failed = {"uid": uid, "error": str(exc)}, True
        print(json.dumps(record, indent=1))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
