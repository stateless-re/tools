import argparse
import base64
import hashlib
import json
import mmap
import os
import re
import struct
import sys
import zlib
from pathlib import Path

import dnfile
import pefile
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BUNDLE_SIGNATURE = bytes.fromhex("8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae")
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
LDSTR = 0x72
CALL = 0x28
STSFLD = 0x80
LDC_SHORT = {0x15: -1, **{0x16 + i: i for i in range(9)}}
BACKING_FIELD = re.compile(r"<(\w+)>k__BackingField")
PDB_RE = re.compile(rb"[A-Za-z]:\\[\x20-\x7e]{3,240}?\.pdb")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
        if op == 0x1F:
            operand = struct.unpack_from("<b", code, pos)[0]
        elif op == 0x20:
            operand = struct.unpack_from("<i", code, pos)[0]
        elif size in (1, 2, 4, 8) and op != SWITCH:
            operand = struct.unpack_from({1: "<B", 2: "<H", 4: "<I", 8: "<Q"}[size], code, pos)[0]
        pos += size
        out.append((op, operand))
    return out


class Assembly:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pe = pefile.PE(data=data, fast_load=True)
        self.dn = dnfile.dnPE(data=data)
        self.tables = self.dn.net.mdtables

    @property
    def name(self) -> str | None:
        if self.tables.Assembly and self.tables.Assembly.rows:
            return str(self.tables.Assembly.rows[0].Name)
        return None

    def user_string(self, token: int) -> str | None:
        item = self.dn.net.user_strings.get(token & 0xFFFFFF)
        return item.value if item is not None else None

    def user_strings(self) -> list[str]:
        heap = self.dn.net.user_strings
        out = []
        pos = 1
        raw = heap.get_data() if hasattr(heap, "get_data") else heap.__data__
        while pos < len(raw):
            item = heap.get(pos)
            if item is None:
                break
            out.append(item.value)
            length = raw[pos]
            if length & 0x80 == 0:
                head = 1
            elif length & 0xC0 == 0x80:
                length = ((length & 0x3F) << 8) | raw[pos + 1]
                head = 2
            else:
                length = ((length & 0x1F) << 24) | (raw[pos + 1] << 16)
                length |= (raw[pos + 2] << 8) | raw[pos + 3]
                head = 4
            pos += head + length
        return out

    def method_il(self, index: int) -> list[tuple[int, int | None]]:
        row = self.tables.MethodDef.rows[index - 1]
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
            if str(row.TypeName) != name:
                continue
            out = {}
            for ref in row.MethodList:
                out[str(ref.row.Name)] = ref.row_index
            return out
        return {}

    def field_name(self, token: int) -> str | None:
        table = token >> 24
        index = token & 0xFFFFFF
        if table == 0x04:
            return str(self.tables.Field.rows[index - 1].Name)
        if table == 0x0A:
            return str(self.tables.MemberRef.rows[index - 1].Name)
        return None

    def method_name(self, token: int) -> str | None:
        table = token >> 24
        index = token & 0xFFFFFF
        if table == 0x06:
            return str(self.tables.MethodDef.rows[index - 1].Name)
        if table == 0x0A:
            return str(self.tables.MemberRef.rows[index - 1].Name)
        return None

    def resources(self) -> dict[str, bytes]:
        out = {}
        for res in self.dn.net.resources or []:
            if isinstance(res.data, bytes | bytearray):
                out[str(res.name)] = bytes(res.data)
        return out

    def pdb(self) -> str | None:
        match = PDB_RE.search(self.data)
        return match.group().decode() if match else None


def parse_bundle(data: bytes) -> dict | None:
    sig = data.find(BUNDLE_SIGNATURE)
    if sig < 8:
        return None
    pos = struct.unpack_from("<q", data, sig - 8)[0]
    if not 0 < pos < len(data):
        return None

    def read(fmt: str) -> tuple:
        nonlocal pos
        values = struct.unpack_from(fmt, data, pos)
        pos += struct.calcsize(fmt)
        return values

    def read_string() -> str:
        nonlocal pos
        length = shift = 0
        while True:
            byte = data[pos]
            pos += 1
            length |= (byte & 0x7F) << shift
            shift += 7
            if byte < 0x80:
                break
        text = data[pos : pos + length].decode("utf-8")
        pos += length
        return text

    major, minor, count = read("<IIi")
    bundle_id = read_string()
    if major >= 2:
        read("<qqqqQ")
    files = []
    for _ in range(count):
        offset, size = read("<qq")
        compressed = read("<q")[0] if major >= 6 else 0
        kind = read("<B")[0]
        path = read_string()
        files.append((path, offset, size, compressed, kind))
    return {"version": f"{major}.{minor}", "id": bundle_id, "files": files}


def bundle_file(data: bytes, entry: tuple) -> bytes:
    _, offset, size, compressed, _ = entry
    blob = data[offset : offset + (compressed or size)]
    return zlib.decompress(blob, -15) if compressed else blob


def aes_cbc_prefixed_iv(blob: bytes, key: bytes) -> bytes | None:
    if len(blob) < 32 or (len(blob) - 16) % 16:
        return None
    dec = Cipher(algorithms.AES(key), modes.CBC(blob[:16])).decryptor()
    plain = dec.update(blob[16:]) + dec.finalize()
    unpad = padding.PKCS7(128).unpadder()
    try:
        return unpad.update(plain) + unpad.finalize()
    except ValueError:
        return None


def loader_key(text: str) -> bytes:
    return text.ljust(32)[:32].encode("utf-8")


def unwrap_loader(asm: Assembly) -> dict | None:
    resources = asm.resources()
    if not resources:
        return None
    for res_name, blob in resources.items():
        for text in asm.user_strings():
            if len(text) < 8:
                continue
            plain = aes_cbc_prefixed_iv(blob, loader_key(text))
            if plain and plain[:2] == b"MZ":
                return {
                    "resource": res_name,
                    "resource_size": len(blob),
                    "key": text,
                    "payload": plain,
                }
    return None


def obfuscator_key(asm: Assembly) -> str | None:
    methods = asm.type_methods("Obfuscator")
    index = methods.get("Deobfuscate")
    if index:
        for op, operand in asm.method_il(index):
            if op == LDSTR:
                return asm.user_string(operand)
    for row in asm.tables.Constant.rows if asm.tables.Constant else []:
        parent = row.Parent
        if parent.table_name == "Field" and str(parent.row.Name) == "Key":
            return bytes(row.Value.value).decode("utf-16-le")
    return None


def deobfuscate(text: str, key: str) -> str | None:
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError:
        return None
    k = key.encode("utf-8")
    out = bytes(c ^ k[i % len(k)] for i, c in enumerate(raw))
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        return None


def agent_config(asm: Assembly) -> dict | None:
    methods = asm.type_methods("AgentConfig")
    cctor = methods.get(".cctor")
    if not cctor:
        return None
    key = obfuscator_key(asm)
    config = {}
    raw = {}
    junk = {}
    value = None
    encoded = None
    for op, operand in asm.method_il(cctor):
        if op == LDSTR:
            value = asm.user_string(operand)
            encoded = None
        elif op in LDC_SHORT:
            value = LDC_SHORT[op]
        elif op in (0x1F, 0x20):
            value = operand
        elif op == CALL and asm.method_name(operand) == "Deobfuscate":
            encoded = value
            value = deobfuscate(value, key) if key and isinstance(value, str) else None
        elif op == STSFLD:
            name = asm.field_name(operand) or hex(operand)
            match = BACKING_FIELD.fullmatch(name)
            name = match.group(1) if match else name
            if name.startswith("ai_"):
                junk[name] = value
            else:
                config[name] = value
                if encoded is not None:
                    raw[name] = encoded
            value = None
            encoded = None
    for name in [n for n, v in config.items() if v in (0, 1)]:
        if name.startswith(("Enable", "Use", "Hidden", "Encrypt")):
            config[name] = bool(config[name])
    if "_serverPortStr" in config:
        port = config.pop("_serverPortStr")
        config["ServerPort"] = int(port) if isinstance(port, str) and port.isdigit() else port
    return {"obfuscator_key": key, "config": config, "encoded": raw, "junk_fields": junk}


def analyze_assembly(data: bytes, label: str, depth: int = 0) -> list[dict]:
    asm = Assembly(data)
    record = {
        "role": label,
        "sha256": sha256(data),
        "size": len(data),
        "assembly": asm.name,
        "pdb": asm.pdb(),
        "non_framework_refs": sorted(
            str(r.Name)
            for r in (asm.tables.AssemblyRef.rows if asm.tables.AssemblyRef else [])
            if not str(r.Name).startswith(("System", "Microsoft.Win32", "mscorlib", "netstandard"))
        ),
    }
    out = [record]
    agent = agent_config(asm)
    if agent:
        record["role"] = "agent"
        record.update(agent)
        record["hwid_registry_key"] = (
            "HKCU\\Software\\noobsaibotRAT"
            if "Software\\noobsaibotRAT" in asm.user_strings()
            else None
        )
        return out
    if depth < 2:
        loader = unwrap_loader(asm)
        if loader:
            payload = loader.pop("payload")
            record["role"] = "loader"
            record.update(loader)
            record["payload_sha256"] = sha256(payload)
            record["_payload"] = payload
            out.extend(analyze_assembly(payload, "payload", depth + 1))
    return out


def package_files(deps: dict) -> set[str]:
    names = set()
    for target in deps.get("targets", {}).values():
        for library, info in target.items():
            if library.startswith("runtimepack."):
                continue
            for section in ("runtime", "native"):
                for file_path in info.get(section, {}):
                    names.add(file_path.rsplit("/", 1)[-1])
    return names


def extract(path: Path) -> list[dict]:
    with path.open("rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as data:
        bundle = parse_bundle(data)
        if bundle is None:
            return analyze_assembly(bytes(data), "input")
        files = bundle["files"]
        configs = [f for f in files if f[0].endswith(".runtimeconfig.json")]
        main = configs[0][0][: -len(".runtimeconfig.json")] + ".dll" if configs else None
        record = {
            "role": "bundle",
            "path": str(path),
            "sha256": sha256(data),
            "bundle_version": bundle["version"],
            "bundle_id": bundle["id"],
            "file_count": len(files),
            "main_assembly": main,
            "app_files": {},
        }
        out = [record]
        by_name = {entry[0]: entry for entry in files}
        deps = [f for f in files if f[4] == 3]
        app_names = package_files(json.loads(bundle_file(data, deps[0]))) if deps else set()
        if main:
            app_names.add(main)
        for name in sorted(app_names):
            entry = by_name.get(name)
            if entry is None:
                continue
            blob = bundle_file(data, entry)
            record["app_files"][name] = sha256(blob)
        if main in by_name:
            out.extend(analyze_assembly(bundle_file(data, by_name[main]), "main_assembly"))
        return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract NoobSaibotRAT configs from single-file bundles, "
        "the AES loader assembly, or the AgentCore assembly. Static only."
    )
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("-o", "--outdir", type=Path, help="write decrypted payloads here")
    args = parser.parse_args()
    failed = False
    for path in args.files:
        try:
            records = extract(path)
            for rec in records:
                payload = rec.pop("_payload", None)
                if payload is not None and args.outdir:
                    args.outdir.mkdir(parents=True, exist_ok=True)
                    target = args.outdir / sha256(payload)
                    target.write_bytes(payload)
                    os.chmod(target, 0o600)
                    rec["payload_written"] = str(target)
            if not any(r.get("role") == "agent" for r in records):
                failed = True
                records.append({"error": "no AgentConfig found"})
            print(json.dumps({"file": str(path), "records": records}, indent=2))
        except Exception as exc:
            failed = True
            print(json.dumps({"file": str(path), "error": f"{type(exc).__name__}: {exc}"}))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
