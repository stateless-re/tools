import argparse
import hashlib
import itertools
import json
import struct
import sys
from pathlib import Path

import dnfile
import pefile
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

ONE_BYTE_OPERANDS = {
    **dict.fromkeys((0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x1F, 0xDE), 1),
    **dict.fromkeys(range(0x2B, 0x38), 1),
    **dict.fromkeys(range(0x38, 0x45), 4),
    **dict.fromkeys((0x20, 0x22, 0x27, 0x28, 0x29, 0x72, 0x73, 0x74, 0x75, 0x79), 4),
    **dict.fromkeys((0x8C, 0x8D, 0x8F, 0xA3, 0xA4, 0xA5, 0xC2, 0xC6, 0xD0, 0xDD), 4),
    **dict.fromkeys(range(0x6F, 0x72), 4),
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
LDC_I4_S = 0x1F
LDC_I4 = 0x20
DUP = 0x25
CALL = 0x28
CALLVIRT = 0x6F
LDSTR = 0x72
NEWOBJ = 0x73
LDSFLD = 0x7E
STSFLD = 0x80
NEWARR = 0x8D
STELEM_I4 = 0x9E
STELEM_REF = 0xA2
LDTOKEN = 0xD0
XOR = 0x61
ELEMENT_FORMATS = {"Byte": "B", "Int32": "i", "UInt16": "H", "Char": "H"}
CONFIG_TYPE = "ClientDefaults"
CONFIG_FACTORY = ("ClientConfig", "FromDefaults")
STRING_SOURCES = (
    ("BeCtrlBootstrap", "EnsureStarted"),
    ("Persistence", None),
)
PEM_SUFFIX = "public.pem"
BOOLEAN_SETTINGS = {
    "SkipCertValidation",
    "EnableLastChannelMemory",
    "LogEnabled",
    "LogEnableConsole",
}


def decode_il(code: bytes) -> list[tuple[int, int | None]]:
    out = []
    pos = 0
    while pos < len(code):
        op = code[pos]
        pos += 1
        if op == 0xFE:
            op = 0xFE00 | code[pos]
            pos += 1
            size = TWO_BYTE_OPERANDS.get(op & 0xFF, 0)
        elif op == SWITCH:
            size = 4 + 4 * struct.unpack_from("<I", code, pos)[0]
        else:
            size = ONE_BYTE_OPERANDS.get(op, 0)
        operand = None
        if op == LDC_I4_S:
            operand = struct.unpack_from("<b", code, pos)[0]
        elif op == LDC_I4:
            operand = struct.unpack_from("<i", code, pos)[0]
        elif op != SWITCH and size in (1, 2, 4, 8):
            fmt = {1: "<B", 2: "<H", 4: "<I", 8: "<Q"}[size]
            operand = struct.unpack_from(fmt, code, pos)[0]
        pos += size
        out.append((op, operand))
    return out


class Assembly:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pe = pefile.PE(data=data, fast_load=True)
        self.dn = dnfile.dnPE(data=data)
        self.tables = self.dn.net.mdtables
        self.field_rva = {row.Field.row_index: row.Rva for row in self.tables.FieldRva.rows}

    def method_il(self, index: int) -> list[tuple[int, int | None]]:
        row = self.tables.MethodDef.rows[index - 1]
        if not row.Rva:
            return []
        head = self.pe.get_data(row.Rva, 12)
        if head[0] & 3 == 2:
            code = self.pe.get_data(row.Rva + 1, head[0] >> 2)
        else:
            size = struct.unpack_from("<I", head, 4)[0]
            hsize = (struct.unpack_from("<H", head, 0)[0] >> 12) * 4
            code = self.pe.get_data(row.Rva + hsize, size)
        return decode_il(code)

    def type_methods(self, name: str) -> dict[str, int]:
        for row in self.tables.TypeDef.rows:
            if str(row.TypeName) == name:
                return {str(ref.row.Name): ref.row_index for ref in row.MethodList}
        return {}

    def user_string(self, token: int) -> str | None:
        item = self.dn.net.user_strings.get(token & 0xFFFFFF)
        return item.value if item is not None else None

    def member_name(self, token: int) -> str | None:
        table, index = token >> 24, token & 0xFFFFFF
        names = {
            0x01: "TypeRef",
            0x02: "TypeDef",
            0x04: "Field",
            0x06: "MethodDef",
            0x0A: "MemberRef",
        }
        table_name = names.get(table)
        if table_name is None:
            return None
        row = getattr(self.tables, table_name).rows[index - 1]
        return str(row.TypeName if table in (0x01, 0x02) else row.Name)

    def field_data(self, token: int, size: int) -> bytes | None:
        if token >> 24 != 0x04:
            return None
        rva = self.field_rva.get(token & 0xFFFFFF)
        return self.pe.get_data(rva, size) if rva else None

    def resources(self) -> dict[str, bytes]:
        out = {}
        for res in self.dn.net.resources or []:
            if isinstance(res.data, bytes | bytearray):
                out[str(res.name)] = bytes(res.data)
        return out

    def assembly_identity(self) -> dict:
        if not self.tables.Assembly or not self.tables.Assembly.rows:
            return {}
        row = self.tables.Assembly.rows[0]
        version = f"{row.MajorVersion}.{row.MinorVersion}.{row.BuildNumber}.{row.RevisionNumber}"
        return {"name": str(row.Name), "version": version}


def xor_key(asm: Assembly) -> int | None:
    index = asm.type_methods(CONFIG_TYPE).get("D")
    if index is None:
        return None
    il = asm.method_il(index)
    for (op, operand), (next_op, _) in itertools.pairwise(il):
        if next_op == XOR and (op in (LDC_I4_S, LDC_I4) or op in LDC_SHORT):
            value = LDC_SHORT.get(op, operand)
            return value & 0xFF
    return None


class Evaluator:
    def __init__(self, asm: Assembly, key: int | None, known: dict | None = None) -> None:
        self.asm = asm
        self.key = key
        self.known = known or {}
        self.stack: list = []
        self.assigned: dict = {}

    def push_array(self, operand: int) -> None:
        count = self.stack.pop()
        kind = self.asm.member_name(operand) or "?"
        self.stack.append({"kind": kind, "items": [None] * count})

    def init_array(self) -> None:
        token = self.stack.pop()
        array = self.stack.pop()
        fmt = ELEMENT_FORMATS.get(array["kind"])
        if fmt is None or not isinstance(token, tuple):
            return
        size = struct.calcsize(fmt) * len(array["items"])
        data = self.asm.field_data(token[1], size)
        if data is not None:
            array["items"][:] = list(struct.unpack(f"<{len(array['items'])}{fmt}", data))

    def decode_string(self) -> None:
        array = self.stack.pop()
        raw = bytes(array["items"])
        self.stack.append(
            "".join(chr(b ^ self.key) for b in raw) if self.key is not None else raw.hex()
        )

    def call(self, operand: int) -> bool:
        name = self.asm.member_name(operand) or ""
        if name == "InitializeArray":
            self.init_array()
        elif name == "D":
            self.decode_string()
        elif name.startswith("set_") and len(self.stack) >= 2:
            value = self.stack.pop()
            self.stack.pop()
            self.assigned[name[4:]] = value
        else:
            return False
        return True

    def step(self, op: int, operand: int | None) -> bool:
        if op in LDC_SHORT:
            self.stack.append(LDC_SHORT[op])
        elif op in (LDC_I4_S, LDC_I4):
            self.stack.append(operand)
        elif op == LDSTR:
            self.stack.append(self.asm.user_string(operand))
        elif op == NEWARR:
            self.push_array(operand)
        elif op == DUP:
            self.stack.append(self.stack[-1])
        elif op == LDTOKEN:
            self.stack.append(("token", operand))
        elif op in (STELEM_REF, STELEM_I4):
            value, index, array = self.stack.pop(), self.stack.pop(), self.stack.pop()
            array["items"][index] = value
        elif op == STSFLD:
            self.assigned[self.asm.member_name(operand)] = self.stack.pop()
        elif op == LDSFLD:
            self.stack.append(self.known.get(self.asm.member_name(operand)))
        elif op == NEWOBJ:
            self.stack.append({"kind": "object", "items": []})
        elif op in (CALL, CALLVIRT):
            return self.call(operand)
        else:
            return False
        return True

    def run(self, il: list[tuple[int, int | None]]) -> dict:
        for op, operand in il:
            try:
                if not self.step(op, operand):
                    break
            except (IndexError, TypeError, KeyError):
                break
        out = {name: plain(value) for name, value in self.assigned.items()}
        for name in BOOLEAN_SETTINGS & out.keys():
            if isinstance(out[name], int):
                out[name] = bool(out[name])
        return out


def plain(value):
    if isinstance(value, dict):
        return [plain(item) for item in value["items"]]
    return value


def method_strings(asm: Assembly, type_name: str, method: str | None) -> list[str]:
    out = []
    for name, index in asm.type_methods(type_name).items():
        if method is not None and name != method:
            continue
        for op, operand in asm.method_il(index):
            if op == LDSTR:
                text = asm.user_string(operand)
                if text and text not in out:
                    out.append(text)
    return out


def rsa_key(asm: Assembly) -> dict | None:
    for name, blob in asm.resources().items():
        if not name.endswith(PEM_SUFFIX):
            continue
        key = load_pem_public_key(blob)
        der = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        numbers = key.public_numbers()
        return {
            "resource": name,
            "bits": key.key_size,
            "exponent": numbers.e,
            "spki_sha256": hashlib.sha256(der).hexdigest(),
            "modulus": format(numbers.n, "x"),
        }
    return None


def extract(path: Path) -> dict:
    data = path.read_bytes()
    record: dict = {"file": str(path), "sha256": hashlib.sha256(data).hexdigest()}
    try:
        asm = Assembly(data)
        methods = asm.type_methods(CONFIG_TYPE)
        if ".cctor" not in methods:
            raise ValueError(f"no {CONFIG_TYPE} static constructor")
        key = xor_key(asm)
        defaults = Evaluator(asm, key).run(asm.method_il(methods[".cctor"]))
        factory_type, factory_method = CONFIG_FACTORY
        factory = asm.type_methods(factory_type).get(factory_method)
        config = Evaluator(asm, key, defaults).run(asm.method_il(factory)) if factory else defaults
        record.update(
            {
                "assembly": asm.assembly_identity(),
                "xor_key": f"0x{key:02x}" if key is not None else None,
                "config": config,
                "rsa_public_key": rsa_key(asm),
                "strings": {
                    f"{type_name}.{method or '*'}": method_strings(asm, type_name, method)
                    for type_name, method in STRING_SOURCES
                },
            }
        )
    except Exception as exc:
        record["error"] = f"{type(exc).__name__}: {exc}"
    return record


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Extract the built-in configuration, RSA key and persistence strings "
            "from Lotuslite V2 (BeCtrl) CommonLib.dll builds."
        )
    )
    parser.add_argument("files", nargs="+", type=Path, help="CommonLib.dll samples")
    args = parser.parse_args()
    records = [extract(path) for path in args.files]
    json.dump(records, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 1 if any("error" in record for record in records) else 0


if __name__ == "__main__":
    sys.exit(main())
