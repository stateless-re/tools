import argparse
import datetime
import hashlib
import json
import lzma
import os
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

import dnfile
import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

ONE_BYTE_OPERANDS = {
    **dict.fromkeys((0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x1F, 0xDE), 1),
    **dict.fromkeys(range(0x2B, 0x38), 1),
    **dict.fromkeys(range(0x38, 0x45), 4),
    **dict.fromkeys((0x20, 0x22, 0x27, 0x28, 0x29, 0x79, 0x8C, 0x8D, 0x8F), 4),
    **dict.fromkeys((0xA3, 0xA4, 0xA5, 0xC2, 0xC6, 0xD0, 0xDD), 4),
    **dict.fromkeys(range(0x6F, 0x76), 4),
    **dict.fromkeys(range(0x7B, 0x82), 4),
    0x21: 8,
    0x23: 8,
}
TWO_BYTE_OPERANDS = {
    0x06: 4,
    0x07: 4,
    0x09: 2,
    0x0A: 2,
    0x0B: 2,
    0x0C: 2,
    0x0D: 2,
    0x0E: 2,
    0x12: 1,
    0x15: 4,
    0x16: 4,
    0x19: 1,
    0x1C: 4,
}
SWITCH = 0x45
LDC_SHORT = {0x15: -1, **{0x16 + i: i for i in range(9)}}
LDLOC_SHORT = {0x06 + i: i for i in range(4)}
STLOC_SHORT = {0x0A + i: i for i in range(4)}
STELEM_I1 = 0x9C
NEWARR = 0x8D
DUP = 0x25
LDTOKEN = 0xD0
CALL = 0x28
MUL = 0x5A
XOR = 0x61
PATH_RE = re.compile(rb"[A-Za-z]:\\[\x20-\x7e]{4,}")
WPATH_RE = re.compile(rb"(?:[A-Za-z]\x00:\x00\\\x00)(?:[\x20-\x7e]\x00){4,}")


@dataclass
class Instr:
    offset: int
    op: int
    operand: int | None


@dataclass
class ByteArray:
    method: int
    local: int
    size: int
    data: list = field(default_factory=list)


def rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def xor_prefixed(blob: bytes, prefix: int) -> bytes:
    key, body = blob[:prefix], blob[prefix:]
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(body))


def printable(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if text and all(c.isprintable() for c in text):
        return text
    return None


def decode_il(code: bytes) -> list[Instr]:
    out = []
    pos = 0
    while pos < len(code):
        start = pos
        op = code[pos]
        pos += 1
        operand = None
        if op == 0xFE:
            op = 0xFE00 | code[pos]
            pos += 1
            size = TWO_BYTE_OPERANDS.get(op & 0xFF, 0)
        elif op == SWITCH:
            count = struct.unpack_from("<I", code, pos)[0]
            size = 4 + 4 * count
        else:
            size = ONE_BYTE_OPERANDS.get(op, 0)
        if size in (1, 2, 4, 8) and op != SWITCH:
            fmt = {1: "<B", 2: "<H", 4: "<I", 8: "<Q"}[size]
            operand = struct.unpack_from(fmt, code, pos)[0]
            if op == 0x1F:
                operand = struct.unpack_from("<b", code, pos)[0]
            if op == 0x20:
                operand = struct.unpack_from("<i", code, pos)[0]
        pos += size
        out.append(Instr(start, op, operand))
    return out


def ldc_value(ins: Instr) -> int | None:
    if ins.op in LDC_SHORT:
        return LDC_SHORT[ins.op]
    if ins.op in (0x1F, 0x20):
        return ins.operand
    return None


def ldloc_index(ins: Instr) -> int | None:
    if ins.op in LDLOC_SHORT:
        return LDLOC_SHORT[ins.op]
    if ins.op == 0x11 or ins.op == 0xFE0C:
        return ins.operand
    return None


def stloc_index(ins: Instr) -> int | None:
    if ins.op in STLOC_SHORT:
        return STLOC_SHORT[ins.op]
    if ins.op == 0x13 or ins.op == 0xFE0E:
        return ins.operand
    return None


class Module:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pe = pefile.PE(data=data, fast_load=False)
        self.dn = dnfile.dnPE(data=data)
        self.tables = self.dn.net.mdtables
        self.byte_type_tokens = self._byte_type_tokens()
        self.field_blobs = self._field_blobs()

    def _byte_type_tokens(self) -> set[int]:
        out = set()
        for i, row in enumerate(self.tables.TypeRef.rows if self.tables.TypeRef else [], 1):
            if str(row.TypeName) == "Byte" and str(row.TypeNamespace) == "System":
                out.add(0x01000000 | i)
        return out

    def _field_blobs(self) -> dict[int, tuple[int, bytes]]:
        sizes = {}
        if self.tables.ClassLayout:
            for row in self.tables.ClassLayout.rows:
                sizes[row.Parent.row_index] = row.ClassSize
        out = {}
        if not self.tables.FieldRva:
            return out
        for row in self.tables.FieldRva.rows:
            sig = bytes(row.Field.row.Signature.value)
            size = None
            if len(sig) > 2 and sig[1] == 0x11 and sig[2] & 3 == 0:
                size = sizes.get(sig[2] >> 2)
            if size:
                out[0x04000000 | row.Field.row_index] = (row.Rva, self.pe.get_data(row.Rva, size))
        return out

    def method_bodies(self):
        for i, row in enumerate(self.tables.MethodDef.rows, 1):
            if not row.Rva:
                continue
            head = self.pe.get_data(row.Rva, 12)
            if head[0] & 3 == 2:
                code = self.pe.get_data(row.Rva + 1, head[0] >> 2)
            else:
                size = struct.unpack_from("<I", head, 4)[0]
                hsize = (struct.unpack_from("<H", head, 0)[0] >> 12) * 4
                code = self.pe.get_data(row.Rva + hsize, size)
            yield 0x06000000 | i, decode_il(code)

    def cli_header(self) -> dict:
        d = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        hdr = self.pe.get_data(d.VirtualAddress, 72)
        flags, entry = struct.unpack_from("<II", hdr, 16)
        vtf_rva, vtf_size = struct.unpack_from("<II", hdr, 48)
        slots = []
        raw = self.pe.get_data(vtf_rva, vtf_size) if vtf_size else b""
        for i in range(len(raw) // 8):
            rva, count, kind = struct.unpack_from("<IHH", raw, i * 8)
            width = 8 if kind & 2 else 4
            for j in range(count):
                tok = int.from_bytes(self.pe.get_data(rva + j * width, width), "little")
                slots.append(
                    {"slot_rva": hex(rva + j * width), "type": hex(kind), "token": f"0x{tok:08x}"}
                )
        return {
            "flags": hex(flags),
            "native_entry_point": bool(flags & 0x10),
            "native_entry_rva": hex(entry) if flags & 0x10 else None,
            "vtable_fixups": slots,
        }


def collect_arrays(mod: Module) -> list[ByteArray]:
    arrays: list[ByteArray] = []
    for token, code in mod.method_bodies():
        by_local: dict[int, list[ByteArray]] = {}
        for k, ins in enumerate(code):
            if ins.op != NEWARR or ins.operand not in mod.byte_type_tokens or k < 1:
                continue
            size = ldc_value(code[k - 1])
            if size is None or size <= 0:
                continue
            arr = ByteArray(token, -1, size, [None] * size)
            nxt = k + 1
            if nxt + 2 < len(code) and code[nxt].op == DUP and code[nxt + 1].op == LDTOKEN:
                blob = mod.field_blobs.get(code[nxt + 1].operand)
                if blob:
                    for i, b in enumerate(blob[1][:size]):
                        arr.data[i] = b
                nxt += 3
            if nxt < len(code):
                loc = stloc_index(code[nxt])
                if loc is not None:
                    arr.local = loc
                    by_local.setdefault(loc, []).append(arr)
            arrays.append(arr)
        for k, ins in enumerate(code):
            if ins.op != STELEM_I1 or k < 3:
                continue
            loc = ldloc_index(code[k - 3])
            idx, val = ldc_value(code[k - 2]), ldc_value(code[k - 1])
            if loc not in by_local or len(by_local[loc]) != 1 or idx is None or val is None:
                continue
            arr = by_local[loc][0]
            if 0 <= idx < arr.size:
                arr.data[idx] = val & 0xFF
    return arrays


def complete(arr: ByteArray) -> bytes:
    return bytes(0 if b is None else b for b in arr.data)


def managed_strings(arrays: list[ByteArray]) -> tuple[str | None, list[str]]:
    keys = [
        complete(a) for a in arrays if a.size == 256 and sum(b is not None for b in a.data) > 200
    ]
    out: list[str] = []
    if keys:
        key = keys[0]
        for a in arrays:
            if a.size in (255, 256):
                continue
            text = printable(rc4(key, complete(a)))
            if text:
                out.append(text)
        if out:
            return key.hex(), out
    for a in arrays:
        if a.size > 255:
            text = printable(xor_prefixed(complete(a), 255))
            if text:
                out.append(text)
    return None, out


def xor_prefix_length(mod: Module) -> int | None:
    found = set()
    for _, code in mod.method_bodies():
        for k, ins in enumerate(code):
            if ins.op == NEWARR and ins.operand in mod.byte_type_tokens and k >= 1:
                size = ldc_value(code[k - 1])
                if size in (32, 255):
                    found.add(size)
    if len(found) == 1:
        return found.pop()
    return None


def xorshift_key(seed: int) -> list[int]:
    out = []
    s = seed & 0xFFFFFFFF
    for _ in range(16):
        s ^= s >> 12
        s ^= (s << 25) & 0xFFFFFFFF
        s ^= s >> 27
        out.append(s)
    return out


def confuser_blob(words: list[int], seed: int) -> bytes:
    key = xorshift_key(seed)
    out = bytearray()
    for off in range(0, len(words), 16):
        block = [words[off + j] ^ key[j] for j in range(16)]
        for j in range(16):
            out += struct.pack("<I", block[j])
            key[j] ^= block[j]
    return bytes(out)


def unlzma(blob: bytes) -> bytes | None:
    props = blob[0]
    if props >= 9 * 5 * 5:
        return None
    size = struct.unpack_from("<I", blob, 5)[0]
    dict_size = struct.unpack_from("<I", blob, 1)[0]
    if size == 0 or size > 0x100000 or dict_size == 0:
        return None
    filt = {
        "id": lzma.FILTER_LZMA1,
        "dict_size": dict_size,
        "lc": props % 9,
        "lp": (props // 9) % 5,
        "pb": props // 45,
    }
    try:
        out = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[filt]).decompress(
            blob[9:], max_length=size
        )
    except lzma.LZMAError:
        return None
    return out if len(out) == size else None


def generic_methods(mod: Module) -> set[int]:
    out = set()
    if not mod.tables.GenericParam:
        return out
    for row in mod.tables.GenericParam.rows:
        owner = row.Owner
        if owner.table is not None and owner.table.name == "MethodDef":
            out.add(0x06000000 | owner.row_index)
    return out


def confuser_constants(mod: Module) -> tuple[dict | None, list[dict]]:
    constants: set[int] = set()
    pairs: set[tuple[int, int]] = set()
    getters = generic_methods(mod)
    for token, code in mod.method_bodies():
        for k, ins in enumerate(code):
            v = ldc_value(ins)
            if v is not None:
                constants.add(v & 0xFFFFFFFF)
            if (
                token in getters
                and ins.op == MUL
                and k >= 1
                and k + 2 < len(code)
                and code[k + 2].op == XOR
            ):
                a, b = ldc_value(code[k - 1]), ldc_value(code[k + 1])
                if a is not None and b is not None:
                    pairs.add((a & 0xFFFFFFFF, b & 0xFFFFFFFF))
    for _, (rva, blob) in mod.field_blobs.items():
        if len(blob) % 64 or not blob:
            continue
        words = list(struct.unpack(f"<{len(blob) // 4}I", blob))
        for seed in constants:
            plain = unlzma(confuser_blob(words, seed))
            if plain is None:
                continue
            strings = []
            for cid in sorted(constants):
                for mul, xr in pairs:
                    v = ((cid * mul) & 0xFFFFFFFF) ^ xr
                    if v >> 30:
                        continue
                    idx = (v & 0x3FFFFFFF) << 2
                    if idx + 4 > len(plain):
                        continue
                    n = struct.unpack_from("<i", plain, idx)[0]
                    if 0 < n <= len(plain) - idx - 4:
                        text = printable(plain[idx + 4 : idx + 4 + n])
                        if text and all(text != s["value"] for s in strings):
                            strings.append({"id": cid, "value": text})
            info = {
                "field_rva": hex(rva),
                "seed": hex(seed),
                "size": len(plain),
                "getters": len(getters),
            }
            return info, strings
    return None, []


def exports(mod: Module) -> dict | None:
    if not hasattr(mod.pe, "DIRECTORY_ENTRY_EXPORT"):
        return None
    exp = mod.pe.DIRECTORY_ENTRY_EXPORT
    targets = sorted({s.forwarder.decode().rsplit(".", 1)[0] for s in exp.symbols if s.forwarder})
    return {
        "dll_name": mod.pe.get_string_at_rva(exp.struct.Name).decode(),
        "count": len(exp.symbols),
        "forwarded": sum(1 for s in exp.symbols if s.forwarder),
        "forward_targets": targets,
    }


def native_paths(mod: Module) -> list[str]:
    out: list[str] = []
    for sec in mod.pe.sections:
        if not sec.Characteristics & 0x40000000:
            continue
        raw = sec.get_data()
        for m in PATH_RE.finditer(raw):
            s = m.group().decode()
            if not re.search(r"\.dll\.#?\w+$", s) and s not in out:
                out.append(s)
        for m in WPATH_RE.finditer(raw):
            s = m.group().decode("utf-16le")
            if s not in out:
                out.append(s)
    return out


def stack_stores(mod: Module, start: int, length: int = 0x600) -> dict[str, dict[int, int]]:
    base = mod.pe.OPTIONAL_HEADER.ImageBase
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    frames: dict[str, dict[int, int]] = {"rsp": {}, "rbp": {}, "rsp_nul": {}, "rbp_nul": {}}
    pat = re.compile(
        r"(dword|byte) ptr \[(rsp|rbp)(?: ([+-]) (0x[0-9a-f]+|\d+))?\], (0x[0-9a-f]+|\d+)$"
    )
    for ins in md.disasm(mod.pe.get_data(start, length), base + start):
        if ins.mnemonic == "ret":
            break
        m = pat.match(ins.op_str)
        if ins.mnemonic != "mov" or not m:
            continue
        off = int(m.group(4), 0) if m.group(4) else 0
        if m.group(3) == "-":
            off = -off
        val = int(m.group(5), 0)
        if m.group(1) == "byte":
            if val == 0:
                frames[m.group(2) + "_nul"][off] = 0
            continue
        for k in range(4):
            frames[m.group(2)][off + k] = (val >> (8 * k)) & 0xFF
    return frames


def native_call_targets(mod: Module, start: int) -> list[int]:
    base = mod.pe.OPTIONAL_HEADER.ImageBase
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    seen: list[int] = []
    todo = [start]
    while todo and len(seen) < 64:
        f = todo.pop(0)
        if f in seen:
            continue
        seen.append(f)
        for ins in md.disasm(mod.pe.get_data(f, 0x600), base + f):
            if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
                target = int(ins.op_str, 16) - base
                sec = mod.pe.get_section_by_rva(target)
                if sec and sec.Characteristics & 0x20000000:
                    todo.append(target)
            if ins.mnemonic in ("lea",) and "rip" in ins.op_str and ins.op_str.startswith("r8,"):
                disp = re.search(r"rip ([+-]) (0x[0-9a-f]+)", ins.op_str)
                if disp:
                    delta = int(disp.group(2), 16) * (1 if disp.group(1) == "+" else -1)
                    todo.append(ins.address + ins.size + delta - base)
            if ins.mnemonic in ("ret", "int3") or (
                ins.mnemonic == "jmp" and not ins.op_str.startswith("0x")
            ):
                break
    return seen


def native_rc4_strings(mod: Module, key: bytes, entry: int) -> list[str]:
    out: list[str] = []
    for func in native_call_targets(mod, entry):
        frames = stack_stores(mod, func)
        if len(frames["rsp"]) + len(frames["rbp"]) < 256:
            continue
        for delta in range(0, 0x400, 4):
            merged = dict(frames["rsp"])
            for off, b in frames["rbp"].items():
                merged[off + delta] = b
            nul = set(frames["rsp_nul"]) | {off + delta for off in frames["rbp_nul"]}
            span = sorted(merged)
            buf = bytes(merged.get(i, 0) for i in range(span[0], span[-1] + 1))
            pos = buf.find(key)
            if pos < 0:
                continue
            used = set(range(span[0] + pos, span[0] + pos + 256))
            run: list[int] = []
            for off in [*span, None]:
                if off is not None and off not in used and (not run or off == run[-1] + 1):
                    run.append(off)
                    continue
                if len(run) >= 4:
                    plain = rc4(key, bytes(merged[i] for i in run))
                    cut = [i - run[0] for i in run if i in nul]
                    plain = plain[: cut[0]] if cut else plain.split(b"\x00")[0]
                    text = printable(plain)
                    if text:
                        out.append(text)
                run = [off] if off is not None and off not in used else []
            return out
    return out


def metadata_roots(data: bytes, pe: pefile.PE) -> list[int]:
    out = []
    pos = data.find(b"BSJB")
    while pos >= 0:
        rva = pe.get_rva_from_offset(pos)
        if rva is not None:
            out.append(rva)
        pos = data.find(b"BSJB", pos + 1)
    return out


def metadata_streams(pe: pefile.PE, rva: int) -> tuple[int, dict[str, tuple[int, int]]]:
    head = pe.get_data(rva, 0x200)
    vlen = struct.unpack_from("<I", head, 12)[0]
    pos = 16 + vlen
    count = struct.unpack_from("<H", head, pos + 2)[0]
    pos += 4
    streams = {}
    end = 0
    for _ in range(count):
        off, size = struct.unpack_from("<II", head, pos)
        pos += 8
        name_end = head.index(0, pos)
        streams[head[pos:name_end].decode()] = (off, size)
        pos = (name_end + 4) & ~3
        end = max(end, off + size)
    return end, streams


def user_strings(pe: pefile.PE, rva: int, size: int) -> list[str]:
    heap = pe.get_data(rva, size)
    out = []
    pos = 1
    while pos < len(heap):
        b = heap[pos]
        if b & 0x80 == 0:
            n, hdr = b, 1
        elif b & 0xC0 == 0x80:
            n, hdr = ((b & 0x3F) << 8) | heap[pos + 1], 2
        else:
            n, hdr = struct.unpack(">I", heap[pos : pos + 4])[0] & 0x1FFFFFFF, 4
        if n == 0:
            pos += hdr
            continue
        text = heap[pos + hdr : pos + hdr + n - 1].decode("utf-16le", "replace")
        if text.strip():
            out.append(text)
        pos += hdr + n
    return out


def original_metadata(data: bytes, mod: Module) -> dict | None:
    cli = mod.pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    hdr_off = mod.pe.get_offset_from_rva(cli.VirtualAddress)
    active = struct.unpack_from("<I", data, hdr_off + 8)[0]
    stale = [r for r in metadata_roots(data, mod.pe) if r != active]
    if not stale:
        return None
    rva = stale[0]
    size, streams = metadata_streams(mod.pe, rva)
    patched = bytearray(data)
    struct.pack_into("<II", patched, hdr_off + 8, rva, size)
    old = dnfile.dnPE(data=bytes(patched))
    t = old.net.mdtables
    methods = [str(r.Name) for r in t.MethodDef.rows] if t.MethodDef else []
    fields = [str(r.Name) for r in t.Field.rows] if t.Field else []
    rvas = {}
    if t.FieldRva:
        for r in t.FieldRva.rows:
            rvas[str(r.Field.row.Name)] = r.Rva
    entry = [re.match(r"__m2mep@\?(\w+)@@", f).group(1) for f in fields if f.startswith("__m2mep@")]
    literals = []
    for f in fields:
        if f.startswith("??_C@") and f in rvas:
            raw = mod.pe.get_data(rvas[f], 0x200)
            if "_1" in f.split("@")[1][:3]:
                text = raw.decode("utf-16le", "replace").split("\x00")[0]
            else:
                text = raw.split(b"\x00")[0].decode("latin-1")
            literals.append(text)
    us = []
    if "#US" in streams:
        off, sz = streams["#US"]
        us = user_strings(mod.pe, rva + off, sz)
    return {
        "metadata_rva": hex(rva),
        "active_metadata_rva": hex(active),
        "methods": [m for m in methods if not m.startswith(".")],
        "managed_entry_points": entry,
        "native_import_pointers": sum(1 for f in fields if f.startswith("__unep@")),
        "cpp_literals": literals,
        "user_strings": us,
    }


def extract(path: Path) -> dict:
    data = path.read_bytes()
    rec: dict = {"file": str(path), "sha256": hashlib.sha256(data).hexdigest()}
    mod = Module(data)
    rec["pe_timestamp"] = datetime.datetime.fromtimestamp(
        mod.pe.FILE_HEADER.TimeDateStamp, datetime.UTC
    ).isoformat()
    opt = mod.pe.OPTIONAL_HEADER
    rec["linker"] = f"{opt.MajorLinkerVersion}.{opt.MinorLinkerVersion}"
    rec["clr"] = mod.cli_header()
    rec["exports"] = exports(mod)
    imports = sorted(
        i.name.decode()
        for d in getattr(mod.pe, "DIRECTORY_ENTRY_IMPORT", [])
        for i in d.imports
        if i.name
    )
    rec["import_count"] = len(imports)
    arrays = collect_arrays(mod)
    key_hex, strings = managed_strings(arrays)
    rec["cipher"] = None
    if key_hex:
        rec["cipher"] = "rc4"
        rec["rc4_key"] = key_hex
    else:
        prefix = xor_prefix_length(mod)
        if prefix:
            rec["cipher"] = "xor-key-prefix"
            rec["xor_prefix_length"] = prefix
    rec["strings"] = strings
    info, cstrings = confuser_constants(mod)
    if info:
        rec["confuserex_constants"] = info
        rec["strings"] += [s["value"] for s in cstrings if s["value"] not in rec["strings"]]
    rec["native_paths"] = native_paths(mod)
    rec["original_metadata"] = original_metadata(data, mod)
    entry = rec["clr"]["native_entry_rva"]
    if key_hex and entry:
        rec["native_rc4_strings"] = native_rc4_strings(mod, bytes.fromhex(key_hex), int(entry, 16))
    return rec


def decrypt_payload(rec: dict, payload: Path, outdir: Path) -> str:
    blob = payload.read_bytes()
    if rec.get("cipher") == "rc4":
        plain = rc4(bytes.fromhex(rec["rc4_key"]), blob)
    elif rec.get("cipher") == "xor-key-prefix":
        plain = xor_prefixed(blob, rec["xor_prefix_length"])
    else:
        raise ValueError("no cipher recovered for this loader")
    digest = hashlib.sha256(plain).hexdigest()
    outdir.mkdir(parents=True, exist_ok=True)
    target = outdir / digest
    target.write_bytes(plain)
    os.chmod(target, 0o600)
    return str(target)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Static config extractor for Turla CerealLoader (mixed-mode .NET loader): "
        "proxy exports, VTableFixup targets, payload and log paths, RC4 or key-prefix XOR scheme."
    )
    ap.add_argument("files", nargs="+", type=Path, help="CerealLoader DLLs")
    ap.add_argument(
        "--payload",
        type=Path,
        help="encrypted payload file to decrypt with the first loader's scheme",
    )
    ap.add_argument(
        "-o",
        "--outdir",
        type=Path,
        default=Path("."),
        help="where --payload output goes (named by SHA-256)",
    )
    args = ap.parse_args()
    status = 0
    results = []
    for f in args.files:
        try:
            results.append(extract(f))
        except Exception as exc:
            results.append({"file": str(f), "error": f"{type(exc).__name__}: {exc}"})
            status = 1
    if args.payload and results and "error" not in results[0]:
        try:
            results[0]["payload_written"] = decrypt_payload(results[0], args.payload, args.outdir)
        except Exception as exc:
            results[0]["error"] = f"payload: {exc}"
            status = 1
    json.dump(results, sys.stdout, indent=2)
    print()
    return status


if __name__ == "__main__":
    sys.exit(main())
