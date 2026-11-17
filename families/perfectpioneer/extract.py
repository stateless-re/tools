import argparse
import hashlib
import json
import os
import re
import struct
import sys
from dataclasses import dataclass, field

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

CONTAINER_MARKER = re.compile(rb"INJECT_\d\d")
MZ_STUB = b"MZ\x90\x00\x03\x00"
PCLNTAB_MAGIC = b"\xf1\xff\xff\xff\x00\x00\x01\x08"
PROJECT_PATH = re.compile(rb"D:/proj/(?:http3/)?[A-Za-z0-9_.-]+")
GO_MODULE = re.compile(rb"\nmod\t([^\t\n]+)")
URL = re.compile(rb"https?://[A-Za-z0-9.-]+:\d{2,5}")
HOST_FORMAT = re.compile(rb"%s\\([A-Za-z0-9_.-]+\.exe)")
RUN_VALUE = b"WindowsSecurityUpdate"
STACK_STRING_DELTA = 0x10
MAX_DEPTH = 6
SECURITY_DIRECTORY = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]


@dataclass
class Node:
    kind: str
    sha256: str
    size: int
    offset: int | None = None
    details: dict = field(default_factory=dict)
    children: list["Node"] = field(default_factory=list)

    def as_dict(self) -> dict:
        out = {"kind": self.kind, "sha256": self.sha256, "size": self.size}
        if self.offset is not None:
            out["offset"] = self.offset
        out.update(self.details)
        if self.children:
            out["children"] = [c.as_dict() for c in self.children]
        return out


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_pe(data: bytes) -> pefile.PE | None:
    try:
        return pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError:
        return None


def pe_raw_size(pe: pefile.PE) -> int:
    end = pe.OPTIONAL_HEADER.SizeOfHeaders
    for s in pe.sections:
        end = max(end, s.PointerToRawData + s.SizeOfRawData)
    security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[SECURITY_DIRECTORY]
    if security.Size and security.VirtualAddress >= end:
        end = security.VirtualAddress + security.Size
    return end


def embedded_pes(data: bytes, start: int = 1) -> list[tuple[int, bytes]]:
    found = []
    pos = start
    while True:
        pos = data.find(MZ_STUB, pos)
        if pos < 0:
            return found
        pe = parse_pe(data[pos:])
        if pe is not None and pe.FILE_HEADER.NumberOfSections:
            size = pe_raw_size(pe)
            if pos + size <= len(data):
                found.append((pos, data[pos : pos + size]))
                pos += size
                continue
        pos += 2


def security_blob(pe: pefile.PE, data: bytes) -> tuple[int, bytes] | None:
    entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    ]
    if not entry.Size or entry.VirtualAddress + 8 > len(data):
        return None
    table = data[entry.VirtualAddress : entry.VirtualAddress + entry.Size]
    if table[8:10] != b"\x30\x82":
        return None
    der_len = struct.unpack(">H", table[10:12])[0] + 4
    start = 8 + der_len
    return entry.VirtualAddress + start, table[start:]


def signature_digest_ok(data: bytes) -> bool | None:
    try:
        import lief
    except ImportError:
        return None
    lief.logging.disable()
    binary = lief.PE.parse(list(data))
    if binary is None or not binary.has_signatures:
        return None
    sig = binary.signatures[0]
    return binary.authentihash(sig.digest_algorithm) == bytes(sig.content_info.digest)


def xor(data: bytes, key: int) -> bytes:
    table = bytes(b ^ key for b in range(256))
    return data.translate(table)


def stub_strings(stub: bytes) -> list[str]:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    out, current = [], []
    for ins in md.disasm(stub, 0):
        m = re.fullmatch(r"byte ptr \[rsp \+ 0x[0-9a-f]+\], (0x[0-9a-f]+|\d+)", ins.op_str)
        if ins.mnemonic == "mov" and m:
            current.append(int(m.group(1), 0))
            continue
        if len(current) > 3 and current[-1] == 0:
            text = bytes((c - STACK_STRING_DELTA) & 0xFF for c in current[:-1])
            if text.isascii() and text.decode().isprintable():
                out.append(text.decode())
        current = []
    return out


def parse_container(blob: bytes, file_offset: int) -> Node | None:
    for key in (0, 0xAA):
        data = xor(blob[:0x400], key) if key else blob[:0x400]
        m = CONTAINER_MARKER.search(data)
        if m and m.start() < 0x40:
            body = xor(blob, key) if key else blob
            pos = m.start()
            name = body[pos + 9 : pos + 0x29].split(b"\0")[0].decode("latin-1")
            size = struct.unpack("<I", body[pos + 0x29 : pos + 0x2D])[0]
            code = body[pos + 0x2D : pos + 0x2D + size]
            return container_node(
                code, file_offset + pos + 0x2D, key, m.group().decode(), name, size
            )
        if data.startswith(b"\x48\x81\xec"):
            body = xor(blob, key) if key else blob
            return container_node(body, file_offset, key, None, None, len(body))
    return None


def container_node(
    code: bytes, offset: int, key: int, marker: str | None, name: str | None, size: int
) -> Node | None:
    pes = embedded_pes(code, 0)
    if not pes:
        return None
    pe_offset = pes[0][0]
    details = {
        "xor_key": key,
        "marker": marker,
        "name": name,
        "declared_size": size,
        "stub_size": pe_offset,
        "stub_strings": stub_strings(code[:pe_offset]),
    }
    node = Node("shellcode", sha256(code), len(code), offset, details)
    return node


def iat_names(pe: pefile.PE) -> dict[int, str]:
    names = {}
    for imp in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for sym in imp.imports:
            if sym.name:
                names[sym.address] = sym.name.decode()
    return names


def loader_details(pe: pefile.PE, data: bytes) -> dict | None:
    names = iat_names(pe)
    if "SetFilePointer" not in names.values() or "ReadFile" not in names.values():
        return None
    is64 = pe.FILE_HEADER.Machine == 0x8664
    md = Cs(CS_ARCH_X86, CS_MODE_64 if is64 else CS_MODE_32)
    base = pe.OPTIONAL_HEADER.ImageBase
    text = next(s for s in pe.sections if s.Name.startswith(b".text"))
    code = text.get_data()
    start = base + text.VirtualAddress
    recent: list = []
    found: dict = {}
    xor_keys = set()
    for ins in md.disasm(code, start):
        target = None
        if ins.mnemonic == "call":
            m = re.fullmatch(r"(?:qword|dword) ptr \[(?:rip \+ )?(0x[0-9a-f]+)\]", ins.op_str)
            if m:
                target = int(m.group(1), 16) + (ins.address + ins.size if is64 else 0)
        if target in names:
            api = names[target]
            if api in ("SetFilePointer", "VirtualAlloc") and api not in found:
                found[api] = immediate_argument(recent, is64)
        m = re.fullmatch(r"byte ptr \[[a-z0-9]+\], (0x[0-9a-f]+)", ins.op_str)
        if ins.mnemonic == "xor" and m:
            xor_keys.add(int(m.group(1), 16))
        recent = [*recent[-8:], ins]
    if "SetFilePointer" not in found:
        return None
    host = HOST_FORMAT.search(data)
    exports = loader_exports(pe, md)
    return {
        "host_file": host.group(1).decode() if host else "own executable",
        "read_offset": found.get("SetFilePointer"),
        "read_size": found.get("VirtualAlloc"),
        "xor_key": sorted(xor_keys)[0] if xor_keys else 0,
        "run_value": RUN_VALUE.decode() if RUN_VALUE in data else None,
        "trigger_exports": exports,
        "export_dll_name": pe.DIRECTORY_ENTRY_EXPORT.name.decode()
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT")
        else None,
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
    }


def immediate_argument(recent: list, is64: bool) -> int | None:
    for ins in reversed(recent):
        if is64 and ins.mnemonic == "mov" and ins.op_str.startswith("edx, 0x"):
            return int(ins.op_str.split(", ")[1], 16)
        if not is64 and ins.mnemonic == "push" and ins.op_str.startswith("0x"):
            return int(ins.op_str, 16)
    return None


def loader_exports(pe: pefile.PE, md: Cs) -> list[str]:
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return []
    base = pe.OPTIONAL_HEADER.ImageBase
    out = []
    for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        code = pe.get_data(sym.address, 8)
        first = next(md.disasm(code, base + sym.address), None)
        if first is not None and first.mnemonic != "ret" and sym.name:
            out.append(sym.name.decode())
    return out


def go_functions(data: bytes) -> list[list[tuple[int, str]]]:
    tables = []
    pos = 0
    while True:
        pos = data.find(PCLNTAB_MAGIC, pos)
        if pos < 0:
            return tables
        t = data[pos:]
        try:
            nfunc, _, text_start, name_off, _, _, _, pcln_off = struct.unpack_from("<8Q", t, 8)
            funcs = []
            for k in range(nfunc):
                entry, func_off = struct.unpack_from("<II", t, pcln_off + k * 8)
                name_rel = struct.unpack_from("<i", t, pcln_off + func_off + 4)[0]
                raw = t[name_off + name_rel : name_off + name_rel + 256]
                funcs.append((text_start + entry, raw.split(b"\0")[0].decode("utf-8", "replace")))
            tables.append(funcs)
        except (struct.error, IndexError):
            pass
        pos += 8


def go_client_config(pe: pefile.PE, data: bytes) -> dict | None:
    tables = go_functions(data)
    if not tables:
        return None
    funcs = sorted(tables[0])
    by_name = {n: a for a, n in funcs}
    main = by_name.get("main.main")
    ctor = next((a for a, n in funcs if n.endswith("internal/agent.NewClient")), None)
    if main is None or ctor is None:
        return None
    end = next(a for a, _ in funcs if a > main)
    base = pe.OPTIONAL_HEADER.ImageBase
    image = pe.get_memory_mapped_image()
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    regs: dict[str, int] = {}
    for ins in md.disasm(image[main - base : end - base], main):
        m = re.fullmatch(r"(r[a-z0-9]+), \[rip \+ (0x[0-9a-f]+)\]", ins.op_str)
        if ins.mnemonic == "lea" and m:
            regs[m.group(1)] = ins.address + ins.size + int(m.group(2), 16)
            continue
        m = re.fullmatch(r"([a-z0-9]+), (0x[0-9a-f]+|\d+)", ins.op_str)
        if ins.mnemonic == "mov" and m:
            regs[m.group(1)] = int(m.group(2), 0)
            continue
        if ins.mnemonic == "call" and ins.op_str == hex(ctor):
            pairs = (("url", "rax", "ebx"), ("username", "rcx", "edi"), ("password", "rsi", "r8d"))
            out = {}
            for key, ptr, length in pairs:
                if ptr in regs and length in regs:
                    raw = image[regs[ptr] - base : regs[ptr] - base + regs[length]]
                    out[key] = raw.decode("utf-8", "replace")
            return out or None
    return None


def analyze(data: bytes, depth: int = 0, offset: int | None = None) -> Node:
    pe = parse_pe(data)
    if pe is None:
        return Node("unknown", sha256(data), len(data), offset)
    node = Node("pe", sha256(data), len(data), offset)
    node.details["machine"] = hex(pe.FILE_HEADER.Machine)
    if depth >= MAX_DEPTH:
        return node
    loader = loader_details(pe, data)
    if loader:
        node.kind = "loader"
        node.details.update(loader)
        return node
    blob = security_blob(pe, data)
    if blob:
        container = parse_container(blob[1], blob[0])
        if container:
            node.kind = "signed_host"
            node.details["signature_digest_matches"] = signature_digest_ok(data)
            pe_offset = container.details["stub_size"]
            code_end = container.offset + container.size
            payload = data[container.offset : code_end]
            if container.details["xor_key"]:
                payload = xor(payload, container.details["xor_key"])
            inner = embedded_pes(payload, 0)
            if inner and inner[0][0] == pe_offset:
                container.children.append(analyze(inner[0][1], depth + 1, inner[0][0]))
            node.children.append(container)
            return node
    if PCLNTAB_MAGIC in data:
        node.kind = "go"
        project = PROJECT_PATH.search(data)
        module = GO_MODULE.search(data)
        node.details["project"] = project.group().decode() if project else None
        node.details["module"] = module.group(1).decode() if module else None
        node.details["config"] = go_client_config(pe, data)
        node.details["urls"] = sorted({u.decode() for u in URL.findall(data)})
    own_end = pe_raw_size(pe)
    for pos, inner in embedded_pes(data[:own_end], 1):
        node.children.append(analyze(inner, depth + 1, pos))
    if node.children and node.kind == "go":
        node.kind = "go_dropper"
    return node


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Unpack PerfectPioneer RAT delivery chains (Go dropper, proxy-DLL loader, "
        "certificate-table container, reflective stub) and print agent configs as JSON."
    )
    parser.add_argument("files", nargs="+", help="files to analyze")
    parser.add_argument("-o", "--out", help="directory to write unpacked PEs (named by SHA-256)")
    args = parser.parse_args()
    status = 0
    for path in args.files:
        try:
            with open(path, "rb") as handle:
                data = handle.read()
            node = analyze(data)
            record = {"file": path, **node.as_dict()}
            if node.kind in ("pe", "unknown") and not node.children:
                record["error"] = "no PerfectPioneer chain traits found"
                status = 1
            if args.out:
                write_payloads(data, args.out)
        except Exception as exc:
            record = {"file": path, "error": f"{type(exc).__name__}: {exc}"}
            status = 1
        print(json.dumps(record, indent=2))
    return status


def write_payloads(data: bytes, out: str) -> None:
    os.makedirs(out, exist_ok=True)
    for blob in collect(data):
        target = os.path.join(out, sha256(blob))
        with open(target, "wb") as handle:
            handle.write(blob)
        os.chmod(target, 0o600)


def collect(data: bytes) -> list[bytes]:
    out = [inner for _, inner in embedded_pes(data, 1)]
    pe = parse_pe(data)
    blob = security_blob(pe, data) if pe is not None else None
    container = parse_container(blob[1], blob[0]) if blob else None
    if container:
        payload = data[container.offset : container.offset + container.size]
        if container.details["xor_key"]:
            payload = xor(payload, container.details["xor_key"])
        out.extend(inner for _, inner in embedded_pes(payload, 0))
    return out


if __name__ == "__main__":
    sys.exit(main())
