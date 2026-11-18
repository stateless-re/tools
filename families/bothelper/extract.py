import argparse
import base64
import hashlib
import json
import os
import re
import struct
import sys
from pathlib import Path

import dnfile
import pefile
from cryptography import x509
from cryptography.hazmat.primitives import hashes

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
LDSFLD = 0x7E
CLR_32BIT_REQUIRED = 0x2
DEFAULT_SEED = 0xA7
DEFAULT_MULTIPLIER = 31
XOR_LOOP = re.compile(
    rb"\xba(.{4})\x89\xd1\x30\x54\x05\x00\xc1\xe1(.)\x29\xd1\x8d\x14\x01", re.DOTALL
)
CONNECT_PORT = re.compile(rb"\x45\x31\xc9\x41\xb8(.{4})\x48\x8d\x15", re.DOTALL)
DROP_NAME = re.compile(rb"%s\\([\w.-]+\.exe)\x00")
WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
DOMAIN = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$", re.IGNORECASE)


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
        if size == 4 and op != SWITCH:
            operand = struct.unpack_from("<I", code, pos)[0]
        pos += size
        out.append((op, operand))
    return out


class Assembly:
    def __init__(self, data: bytes) -> None:
        self.pe = pefile.PE(data=data, fast_load=True)
        self.dn = dnfile.dnPE(data=data)
        self.tables = self.dn.net.mdtables
        self.field_owner = self.map_field_owners()

    def map_field_owners(self) -> dict[int, str]:
        owners = {}
        for row in self.tables.TypeDef.rows:
            name = f"{row.TypeNamespace}.{row.TypeName}".lstrip(".")
            for ref in row.FieldList:
                owners[ref.row_index] = name
        return owners

    def methods(self):
        for row in self.tables.TypeDef.rows:
            name = f"{row.TypeNamespace}.{row.TypeName}".lstrip(".")
            for ref in row.MethodList:
                yield name, str(ref.row.Name), ref.row

    def method_il(self, row) -> list[tuple[int, int | None]]:
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

    def user_string(self, token: int) -> str | None:
        item = self.dn.net.user_strings.get(token & 0xFFFFFF)
        return item.value if item is not None else None

    def field(self, token: int) -> str | None:
        if token >> 24 != 0x04:
            return None
        index = token & 0xFFFFFF
        name = str(self.tables.Field.rows[index - 1].Name)
        return f"{self.field_owner.get(index, '?')}.{name}"

    def member_name(self, token: int) -> str | None:
        table = token >> 24
        index = token & 0xFFFFFF
        if table == 0x06:
            return str(self.tables.MethodDef.rows[index - 1].Name)
        if table == 0x0A:
            return str(self.tables.MemberRef.rows[index - 1].Name)
        return None


def static_assignments(asm: Assembly) -> tuple[dict[str, str], set[str], set[str]]:
    values = {}
    stored = set()
    loaded = set()
    for _, _, row in asm.methods():
        pending: list[str] = []
        for op, operand in asm.method_il(row):
            if op == LDSTR:
                pending.append(asm.user_string(operand) or "")
            elif op == CALL:
                name = asm.member_name(operand)
                if name == "get_UserName":
                    pending.append("<user>")
                elif name == "Concat" and pending:
                    pending = ["".join(pending)]
            elif op == STSFLD:
                name = asm.field(operand)
                if name:
                    stored.add(name)
                    if pending:
                        values[name] = pending[-1]
                pending = []
            elif op == LDSFLD:
                name = asm.field(operand)
                if name:
                    loaded.add(name)
            elif op not in (0x8D, 0x25, 0x16, 0x17, 0xA2, 0x9A):
                pending = []
    return values, stored, loaded


def method_strings(asm: Assembly, marker: str) -> list[str]:
    for _, _, row in asm.methods():
        strings = [asm.user_string(o) for op, o in asm.method_il(row) if op == LDSTR]
        if marker in strings:
            return [s for s in strings if s]
    return []


def certificate(asm: Assembly) -> dict | None:
    for _, _, row in asm.methods():
        for op, operand in asm.method_il(row):
            if op != LDSTR:
                continue
            text = asm.user_string(operand) or ""
            if not text.startswith("MII"):
                continue
            cert = x509.load_der_x509_certificate(base64.b64decode(text))
            return {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial": f"{cert.serial_number:X}",
                "not_before": cert.not_valid_before_utc.isoformat(),
                "not_after": cert.not_valid_after_utc.isoformat(),
                "sha256": cert.fingerprint(hashes.SHA256()).hex(),
                "sha1": cert.fingerprint(hashes.SHA1()).hex(),
            }
    return None


def parse_rat(data: bytes) -> dict:
    asm = Assembly(data)
    values, stored, loaded = static_assignments(asm)
    config = {}
    for name, value in values.items():
        owner, _, field = name.rpartition(".")
        if owner.endswith(("AppConfig", "ServiceClient")):
            config[field] = value
    commands = method_strings(asm, "Screenshot")
    user_strings = []
    heap = asm.dn.net.user_strings
    raw = heap.get_data() if hasattr(heap, "get_data") else heap.__data__
    pos = 1
    while pos < len(raw):
        item = heap.get(pos)
        if item is None:
            break
        user_strings.append(item.value)
        length = raw[pos]
        head = 1 if length < 0x80 else 2
        if length >= 0x80:
            length = ((length & 0x3F) << 8) | raw[pos + 1]
        pos += head + length
    net_tasks = sorted({s for s in user_strings if s.startswith("NetTask") and len(s) > 7})
    anti_vm = [n for n in stored | loaded if n.endswith("EnvironmentCheck.Enabled")]
    unread = sorted(
        n.rpartition(".")[2]
        for n in stored
        if n.rpartition(".")[0].endswith("AppConfig") and n not in loaded
    )
    flags = asm.dn.net.struct.Flags
    flags = flags if isinstance(flags, int) else int(flags.value)
    return {
        "role": "rat",
        "config": config,
        "certificate": certificate(asm),
        "commands": list(dict.fromkeys(c for c in commands if c[:1].isupper() and "." not in c)),
        "net_tasks": net_tasks,
        "anti_vm_flag_ever_set": any(n in stored for n in anti_vm),
        "config_fields_never_read": unread,
        "clr_32bit_required": bool(flags & CLR_32BIT_REQUIRED),
    }


def wide_strings(data: bytes) -> list[str]:
    return [m.group().decode("utf-16le") for m in WIDE.finditer(data)]


def parse_stager(data: bytes) -> dict:
    out: dict = {"role": "stager"}
    strings = wide_strings(data)
    host = next((s for s in strings if DOMAIN.match(s)), None)
    path = next((s for s in strings if s.startswith("/")), None)
    agent = next((s for s in strings if s.startswith("Mozilla/")), None)
    port_match = CONNECT_PORT.search(data)
    port = struct.unpack("<I", port_match.group(1))[0] if port_match else None
    out["host"] = host
    out["port"] = port
    out["path"] = path
    if host and path:
        scheme = "https" if port == 443 else "http"
        out["url"] = f"{scheme}://{host}{'' if port in (80, 443, None) else f':{port}'}{path}"
    out["user_agent"] = agent
    loop = XOR_LOOP.search(data)
    if loop:
        out["xor_seed"] = struct.unpack("<I", loop.group(1))[0] & 0xFF
        out["xor_multiplier"] = (1 << loop.group(2)[0]) - 1
    drop = DROP_NAME.search(data)
    out["drop_name"] = drop.group(1).decode() if drop else None
    return out


def xor_decrypt(data: bytes, seed: int, multiplier: int) -> bytes:
    out = bytearray(data)
    key = seed
    for i in range(len(out)):
        out[i] ^= key & 0xFF
        key = (key * multiplier + i) & 0xFFFFFFFF
    return bytes(out)


def parse_container(plain: bytes) -> dict:
    decoy_len = struct.unpack_from("<I", plain, 0)[0]
    name_at = 4 + decoy_len
    if name_at + 4 > len(plain):
        raise ValueError("decoy length runs past the buffer")
    name_len = struct.unpack_from("<I", plain, name_at)[0]
    payload_at = name_at + 4 + name_len
    if payload_at > len(plain):
        raise ValueError("name length runs past the buffer")
    name = plain[name_at + 4 : payload_at].split(b"\x00")[0].decode("latin-1")
    return {
        "decoy": plain[4:name_at],
        "decoy_name": name,
        "payload": plain[payload_at:],
    }


def write_out(outdir: Path, blob: bytes) -> str:
    digest = sha256(blob)
    path = outdir / digest
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(blob)
    return digest


def parse_payload(data: bytes, seed: int, multiplier: int, outdir: Path | None) -> dict:
    parts = parse_container(xor_decrypt(data, seed, multiplier))
    payload = parts["payload"]
    out = {
        "role": "payload_container",
        "xor_seed": seed,
        "xor_multiplier": multiplier,
        "decoy_size": len(parts["decoy"]),
        "decoy_name": parts["decoy_name"] or None,
        "payload_size": len(payload),
        "payload_sha256": sha256(payload),
        "payload_is_pe": payload[:2] == b"MZ",
    }
    if parts["decoy"]:
        out["decoy_sha256"] = sha256(parts["decoy"])
    if outdir:
        outdir.mkdir(parents=True, exist_ok=True)
        write_out(outdir, payload)
        if parts["decoy"]:
            write_out(outdir, parts["decoy"])
    if payload[:2] == b"MZ":
        try:
            out["payload_config"] = parse_rat(payload)
        except Exception as exc:
            out["payload_config_error"] = str(exc)
    return out


def analyze(path: Path, args: argparse.Namespace) -> dict:
    data = path.read_bytes()
    record = {"file": str(path), "sha256": sha256(data)}
    if args.payload:
        record.update(parse_payload(data, args.seed, args.multiplier, args.output))
        return record
    if data[:2] != b"MZ":
        raise ValueError("not a PE; pass --payload for an encrypted payload.bin")
    pe = pefile.PE(data=data, fast_load=True)
    clr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    if clr.VirtualAddress and clr.Size:
        record.update(parse_rat(data))
    else:
        record.update(parse_stager(data))
    return record


def main() -> int:
    parser = argparse.ArgumentParser(
        description="BotHelper RAT static extractor: stager URL and XOR key, RAT config, "
        "and decryption of the stager's payload.bin container"
    )
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument(
        "--payload", action="store_true", help="treat inputs as encrypted payload.bin files"
    )
    parser.add_argument("--seed", type=lambda v: int(v, 0), default=DEFAULT_SEED)
    parser.add_argument("--multiplier", type=lambda v: int(v, 0), default=DEFAULT_MULTIPLIER)
    parser.add_argument(
        "-o", "--output", type=Path, help="write decrypted payload and decoy here (mode 600)"
    )
    args = parser.parse_args()
    failed = False
    results = []
    for path in args.files:
        try:
            results.append(analyze(path, args))
        except Exception as exc:
            failed = True
            results.append({"file": str(path), "error": str(exc)})
    json.dump(results, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
