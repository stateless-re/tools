import argparse
import hashlib
import json
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

OPCODES = {
    1: {
        "UGET": 43,
        "ADDVN": 20,
        "SUBVN": 21,
        "TGETV": 54,
        "RET1": 72,
        "KNUM": 40,
        "FNEW": 49,
        "GSET": 53,
    },
    2: {
        "UGET": 45,
        "ADDVN": 22,
        "SUBVN": 23,
        "TGETV": 56,
        "RET1": 76,
        "KNUM": 42,
        "FNEW": 51,
        "GSET": 55,
    },
}

INDICATOR_PATTERNS = [
    r"^https?://",
    r"CLSID\\",
    r"^%[A-Za-z]+%\\.*(Chrome|PlatformExperienceHelper)",
    r"\.dll$",
    r"k2f",
    r"^/px/$",
    r"^BEARER$",
]


@dataclass
class Proto:
    index: int
    offset: int
    uv: list[int]
    kgc: list[tuple]
    kn: list[Any]
    bc: list[int]

    def gc(self, d: int) -> tuple:
        return self.kgc[len(self.kgc) - 1 - d]


@dataclass
class Dump:
    version: int
    flags: int
    protos: list[Proto] = field(default_factory=list)
    consumed: int = 0


class Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def u8(self) -> int:
        value = self.data[self.pos]
        self.pos += 1
        return value

    def raw(self, size: int) -> bytes:
        if self.pos + size > len(self.data):
            raise ValueError("truncated dump")
        value = self.data[self.pos : self.pos + size]
        self.pos += size
        return value

    def uleb(self) -> int:
        value = 0
        shift = 0
        while True:
            byte = self.u8()
            value |= (byte & 0x7F) << shift
            shift += 7
            if byte < 0x80:
                return value

    def uleb33(self) -> tuple[bool, int]:
        byte = self.u8()
        is_num = bool(byte & 1)
        value = byte >> 1
        if byte >= 0x80:
            value &= 0x3F
            shift = 6
            while True:
                byte = self.u8()
                value |= (byte & 0x7F) << shift
                shift += 7
                if byte < 0x80:
                    break
        return is_num, value


def double(lo: int, hi: int) -> float:
    return struct.unpack("<d", struct.pack("<II", lo & 0xFFFFFFFF, hi & 0xFFFFFFFF))[0]


def table_value(reader: Reader) -> Any:
    tag = reader.uleb()
    if tag == 0:
        return None
    if tag == 1:
        return False
    if tag == 2:
        return True
    if tag == 3:
        return reader.uleb()
    if tag == 4:
        return double(reader.uleb(), reader.uleb())
    return reader.raw(tag - 5)


def parse_dump(data: bytes) -> Dump:
    reader = Reader(data)
    if reader.raw(3) != b"\x1bLJ":
        raise ValueError("not LuaJIT bytecode")
    version = reader.u8()
    if version not in OPCODES:
        raise ValueError(f"unsupported bytecode version {version}")
    flags = reader.uleb()
    if flags & 1:
        raise ValueError("big-endian dumps are not supported")
    if not flags & 2:
        reader.raw(reader.uleb())
    dump = Dump(version, flags)
    pending: list[int] = []
    while reader.pos < len(data):
        length = reader.uleb()
        if length == 0:
            break
        start = reader.pos
        reader.u8()
        reader.u8()
        reader.u8()
        num_uv = reader.u8()
        num_kgc = reader.uleb()
        num_kn = reader.uleb()
        num_bc = reader.uleb()
        debug_size = 0
        if not flags & 2:
            debug_size = reader.uleb()
            if debug_size:
                reader.uleb()
                reader.uleb()
        bc = list(struct.unpack(f"<{num_bc}I", reader.raw(4 * num_bc)))
        uv = list(struct.unpack(f"<{num_uv}H", reader.raw(2 * num_uv)))
        kgc: list[tuple] = []
        for _ in range(num_kgc):
            tag = reader.uleb()
            if tag == 0:
                kgc.append(("child", pending.pop()))
            elif tag == 1:
                narray = reader.uleb()
                nhash = reader.uleb()
                array = [table_value(reader) for _ in range(narray)]
                pairs = [(table_value(reader), table_value(reader)) for _ in range(nhash)]
                kgc.append(("tab", array, pairs))
            elif tag in (2, 3):
                kgc.append(("int64", reader.uleb(), reader.uleb()))
            elif tag == 4:
                kgc.append(("complex", [reader.uleb() for _ in range(4)]))
            else:
                kgc.append(("str", reader.raw(tag - 5)))
        kn: list[Any] = []
        for _ in range(num_kn):
            is_num, value = reader.uleb33()
            if is_num:
                kn.append(double(value, reader.uleb()))
            else:
                kn.append(value - (1 << 32) if value & 0x80000000 else value)
        reader.raw(debug_size)
        if reader.pos != start + length:
            raise ValueError(f"prototype at {start:#x} has a bad length")
        dump.protos.append(Proto(len(dump.protos), start, uv, kgc, kn, bc))
        pending.append(len(dump.protos) - 1)
    dump.consumed = reader.pos
    return dump


def as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def string_table(dump: Dump) -> tuple[Proto, int, list[Any]]:
    best: tuple[int, Proto, int] | None = None
    for proto in dump.protos:
        for d in range(len(proto.kgc)):
            entry = proto.gc(d)
            if entry[0] != "tab" or entry[2]:
                continue
            count = sum(isinstance(v, bytes) for v in entry[1])
            if count >= 16 and (best is None or count > best[0]):
                best = (count, proto, d)
    if best is None:
        raise ValueError("no constant string array found")
    _, proto, d = best
    return proto, d, list(proto.gc(d)[1])


def rotation_pairs(proto: Proto) -> list[tuple[int, int]]:
    pairs = []
    for d in range(len(proto.kgc)):
        entry = proto.gc(d)
        if entry[0] == "tab" and not entry[2] and len(entry[1]) == 3 and entry[1][0] is None:
            first, second = as_int(entry[1][1]), as_int(entry[1][2])
            if first is not None and second is not None:
                pairs.append((first, second))
    return pairs


def alphabets(proto: Proto) -> dict[int, dict[bytes, int]]:
    found: dict[int, dict[bytes, int]] = {}
    for d in range(len(proto.kgc)):
        entry = proto.gc(d)
        if entry[0] != "tab" or entry[1] or len(entry[2]) not in (64, 85):
            continue
        mapping = {k: as_int(v) for k, v in entry[2]}
        if all(isinstance(k, bytes) and len(k) == 1 for k in mapping) and sorted(
            mapping.values()
        ) == list(range(len(mapping))):
            found[len(mapping)] = mapping
    return found


def decode_base64(text: bytes, alphabet: dict[bytes, int]) -> bytes:
    out = bytearray()
    acc = 0
    count = 0
    for i in range(len(text)):
        char = text[i : i + 1]
        value = alphabet.get(char)
        if value is not None:
            acc += value * 64 ** (3 - count)
            count += 1
            if count == 4:
                out += bytes([acc // 65536, acc % 65536 // 256, acc % 256])
                acc = 0
                count = 0
        elif char == b"=":
            out.append(acc // 65536)
            if i + 1 >= len(text) or text[i + 1 : i + 2] != b"=":
                out.append(acc % 65536 // 256)
            break
    return bytes(out)


def decode_base85(text: bytes, alphabet: dict[bytes, int]) -> bytes:
    out = bytearray()
    pos = 0
    while pos < len(text):
        width = min(5, len(text) - pos)
        acc = 0
        valid = width > 1
        for j in range(5):
            if j < width:
                value = alphabet.get(text[pos + j : pos + j + 1])
                if value is None:
                    valid = False
                    break
            else:
                value = 84
            acc = acc * 85 + value
        if valid:
            out += bytes([acc // 16777216 % 256, acc // 65536 % 256, acc // 256 % 256, acc % 256])[
                : width - 1
            ]
        pos += width
    return bytes(out)


def printable_score(values: list[bytes]) -> float:
    total = sum(len(v) for v in values) or 1
    good = sum(sum(32 <= b < 127 or b in (9, 10, 13) for b in v) for v in values)
    return good / total


def decode_table(
    entries: list[Any], tables: dict[int, dict[bytes, int]]
) -> tuple[list[Any], dict[str, str]]:
    if 64 not in tables or 85 not in tables:
        raise ValueError("base64 and base85 alphabets not both present")
    prefixes = sorted({e[:1] for e in entries if isinstance(e, bytes) and e})
    if len(prefixes) != 2:
        raise ValueError(f"expected two encoding prefixes, found {len(prefixes)}")
    best: tuple[float, list[Any], dict[str, str]] | None = None
    for b64, b85 in (prefixes, prefixes[::-1]):
        decoded: list[Any] = []
        for entry in entries:
            if isinstance(entry, bytes) and entry[:1] == b64:
                decoded.append(decode_base64(entry[1:], tables[64]))
            elif isinstance(entry, bytes) and entry[:1] == b85:
                decoded.append(decode_base85(entry[1:], tables[85]))
            else:
                decoded.append(entry)
        score = printable_score([v for v in decoded if isinstance(v, bytes)])
        mapping = {"base64": b64.decode("latin-1"), "base85": b85.decode("latin-1")}
        if best is None or score > best[0]:
            best = (score, decoded, mapping)
    assert best is not None
    return best[1], best[2]


def accessor_offset(dump: Dump, table_proto: Proto) -> int:
    ops = OPCODES[dump.version]
    children = {entry[1] for entry in table_proto.kgc if entry[0] == "child"}
    for index in sorted(children):
        proto = dump.protos[index]
        if len(proto.bc) != 4 or len(proto.kn) != 1:
            continue
        codes = [ins & 0xFF for ins in proto.bc]
        if codes[0] != ops["UGET"] or codes[2] != ops["TGETV"] or codes[3] != ops["RET1"]:
            continue
        constant = as_int(proto.kn[(proto.bc[1] >> 16) & 0xFF])
        if constant is None:
            continue
        if codes[1] == ops["SUBVN"]:
            return -constant
        if codes[1] == ops["ADDVN"]:
            return constant
    raise ValueError("accessor function not found")


def text(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.decode("utf-8", "backslashreplace")
    return value


def lookup(strings: dict[int, Any], proto: Proto, ins: int) -> Any:
    value = as_int(proto.kn[ins >> 16]) if (ins >> 16) < len(proto.kn) else None
    return strings.get(value) if value is not None else None


def registrations(
    dump: Dump, proto: Proto, strings: dict[int, Any]
) -> tuple[list[dict], dict[str, Any]]:
    ops = OPCODES[dump.version]
    modules: list[dict] = []
    globals_: dict[str, Any] = {}
    last_string: Any = None
    for ins in proto.bc:
        op = ins & 0xFF
        if op == ops["KNUM"]:
            last_string = lookup(strings, proto, ins)
        elif op == ops["FNEW"] and isinstance(last_string, str):
            child = proto.gc(ins >> 16)
            modules.append({"name": last_string, "proto": child[1]})
            last_string = None
        elif op == ops["GSET"]:
            name = proto.gc(ins >> 16)
            if name[0] == "str" and last_string is not None:
                globals_[name[1].decode("latin-1")] = last_string
            last_string = None
    return modules, globals_


def analyze(path: Path, include_strings: bool) -> dict[str, Any]:
    data = path.read_bytes()
    record: dict[str, Any] = {
        "file": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }
    dump = parse_dump(data)
    record["bytecode"] = {
        "version": dump.version,
        "luajit": "2.0" if dump.version == 1 else "2.1",
        "stripped": bool(dump.flags & 2),
        "flags": dump.flags,
        "prototypes": len(dump.protos),
        "consumed": dump.consumed,
    }
    proto, _, entries = string_table(dump)
    pairs = rotation_pairs(proto)
    for first, last in pairs:
        while first < last:
            entries[first], entries[last] = entries[last], entries[first]
            first += 1
            last -= 1
    decoded, prefixes = decode_table(entries, alphabets(proto))
    offset = accessor_offset(dump, proto)
    strings = {i - offset: text(v) for i, v in enumerate(decoded) if i > 0}
    modules, globals_ = registrations(dump, proto, strings)
    indicators = sorted(
        {
            v
            for v in strings.values()
            if isinstance(v, str) and any(re.search(p, v) for p in INDICATOR_PATTERNS)
        }
    )
    record["string_table"] = {
        "prototype": proto.index,
        "entries": len(entries) - 1,
        "rotation": [list(p) for p in pairs],
        "prefixes": prefixes,
        "accessor_offset": offset,
        "index_range": [1 - offset, len(entries) - 1 - offset],
    }
    record["globals"] = globals_
    record["build"] = globals_.get("K2F_LUA_BUILD")
    record["modules"] = modules
    record["strings_of_interest"] = indicators
    if include_strings:
        record["strings"] = {str(k): v for k, v in sorted(strings.items())}
    return record


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decode the Prometheus constant array in k2f LuaJIT bundles."
    )
    parser.add_argument("files", nargs="+", type=Path, help="LuaJIT bytecode bundles")
    parser.add_argument(
        "--strings",
        action="store_true",
        help="include every decoded string, keyed by accessor index",
    )
    args = parser.parse_args()
    failed = False
    results = []
    for path in args.files:
        try:
            results.append(analyze(path, args.strings))
        except (OSError, ValueError, IndexError, KeyError) as exc:
            failed = True
            results.append({"file": str(path), "error": str(exc)})
    json.dump(results, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
