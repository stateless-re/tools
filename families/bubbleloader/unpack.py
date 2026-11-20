import argparse
import hashlib
import json
import os
import re
import struct
import sys

import pefile

COPY_SRC = re.compile(rb"\x48\x8d\xb3(.{4})", re.S)
COPY_LEN = re.compile(rb"\xb9(.{4})\xf3\xa4", re.S)
JUMP = re.compile(rb"\x4d\x8d\x92(.{4})\x41\xff\xe2", re.S)
SLEEP = re.compile(rb"\xb9(.{4})", re.S)
WRAPPER = re.compile(
    rb"\x4c\x8d\x1d(.{4})\x4c\x8d\x15(.{4})\x4c\x8d\x0d(.{4})\x48\x8d\x15(.{4})",
    re.S,
)
ADD_RCX = re.compile(rb"\x48\x81\xc1(.{4})", re.S)
ADD_RDX = re.compile(rb"\x48\x81\xc2(.{4})", re.S)
ADD_R8 = re.compile(rb"\x49\x81\xc0(.{4})", re.S)
ADD_RBX = re.compile(rb"(?:\x48\x81\xc3|\x49\x81\xc1)(.{4})", re.S)
UPTIME = re.compile(rb"\x0f\x31.{0,16}\x48\xb9(.{8})", re.S)
TSC_ADD = re.compile(rb"(?<!\x48)\xb9(.{4}).{0,16}?\x48\x8d\x0c\x01", re.S)
KUSER = re.compile(rb"\xb9\x00\x00\xfe\x7f.{0,64}?\xb9(.{4}).{0,16}?\x48\x39\xc8", re.S)
XOR_AA_NAMES = [b"GetLastInputInfo", b"user32.dll"]
BEING_DEBUGGED = re.compile(rb"\x80\x78\x02\x00")
CPUS = re.compile(rb"\x80\xb8\xb8\x00\x00\x00(.)", re.S)
STAGE3_KEY = re.compile(rb"\xe8(.)\x00\x00\x00", re.S)
LEA_R10 = re.compile(rb"\x4c\x8d\x15(.{4})", re.S)
LEA_RDX = re.compile(rb"\x48\x8d\x15(.{4})\x4c\x8d\x05(.{4})", re.S)
URL = re.compile(rb"https?://[\x21-\x7e]{4,200}")


def u32(b: bytes) -> int:
    return struct.unpack("<I", b)[0]


def s32(b: bytes) -> int:
    return struct.unpack("<i", b)[0]


def xor_repeat(data: bytes, key: bytes) -> bytes:
    n = len(key)
    return bytes(c ^ key[i % n] for i, c in enumerate(data))


def resource_of(pe: pefile.PE, rva: int) -> dict | None:
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return None
    for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for n in t.directory.entries:
            for lang in n.directory.entries:
                d = lang.data.struct
                if d.OffsetToData <= rva < d.OffsetToData + d.Size:
                    return {
                        "type": str(t.name) if t.name else t.id,
                        "id": str(n.name) if n.name else n.id,
                        "size": d.Size,
                        "offset_in_resource": rva - d.OffsetToData,
                    }
    return None


def entry_patch(image: bytes, ep: int) -> dict:
    window = image[ep : ep + 0x400]
    src = COPY_SRC.search(window)
    size = COPY_LEN.search(window)
    jump = JUMP.search(window)
    if not (src and size and jump):
        raise ValueError("entry-point patch not recognised")
    sleep = None
    for m in SLEEP.finditer(window[: src.start()]):
        value = u32(m.group(1))
        if 1000 <= value <= 600000 and value != u32(size.group(1)):
            sleep = value
    return {
        "copy_src_rva": u32(src.group(1)),
        "copy_size": u32(size.group(1)),
        "stage2_offset": u32(jump.group(1)),
        "sleep_ms": sleep,
    }


def unwrap_stage2(buf: bytearray, off: int) -> tuple[bytearray, int, dict | None]:
    m = WRAPPER.match(buf, off, off + 0x80) or WRAPPER.search(buf, off, off + 0x80)
    if not m:
        return buf, off, None
    base = m.start()
    start = base + 7 + s32(m.group(1))
    end = base + 14 + s32(m.group(2))
    key_start = base + 21 + s32(m.group(3))
    key_end = base + 28 + s32(m.group(4))
    key = bytes(buf[key_start:key_end])
    buf[start:end] = xor_repeat(bytes(buf[start:end]), key)
    info = {"key": key.hex(), "decrypted": [start, end]}
    return buf, start, info


def stage2(buf: bytearray, off: int, src_rva: int) -> dict:
    code = bytes(buf[off : off + 0x800])
    rcx = [u32(m.group(1)) for m in ADD_RCX.finditer(code)]
    rdx = [u32(m.group(1)) for m in ADD_RDX.finditer(code)]
    r8 = [u32(m.group(1)) for m in ADD_R8.finditer(code)]
    rbx = [u32(m.group(1)) for m in ADD_RBX.finditer(code)]
    if not (rcx and len(rdx) >= 2 and len(r8) >= 3 and rbx):
        raise ValueError("stage 2 not recognised")
    if rcx[0] != src_rva or rdx[0] != src_rva:
        raise ValueError("stage 2 base mismatch")
    gates = {}
    up = UPTIME.search(code)
    if up:
        gates["min_tsc"] = struct.unpack("<Q", up.group(1))[0]
    cpu = CPUS.search(code)
    if cpu:
        gates["min_cpus"] = cpu.group(1)[0]
    adds = [u32(m.group(1)) for m in TSC_ADD.finditer(code)]
    if len(adds) >= 2:
        gates["max_tsc_gap"] = adds[0]
        gates["busy_wait_cycles"] = adds[1]
    kuser = KUSER.search(code)
    if kuser:
        gates["min_interrupt_time_100ns"] = u32(kuser.group(1))
    if BEING_DEBUGGED.search(code):
        gates["peb_being_debugged"] = True
    whole = bytes(buf[off:])
    for name in XOR_AA_NAMES:
        if bytes(c ^ 0xAA for c in name) in whole:
            gates.setdefault("xor_aa_strings", []).append(name.decode())
    return {
        "key_len": rdx[1],
        "enc_len": r8[2],
        "stage3_entry": rbx[0] - src_rva,
        "gates": gates,
    }


def stage3(blob: bytes) -> dict:
    for m in STAGE3_KEY.finditer(blob):
        n = m.group(1)[0]
        if not 4 <= n <= 64:
            continue
        k0 = m.end()
        key_end = k0 + n
        r10 = LEA_R10.search(blob, key_end, key_end + 0x30)
        if not r10 or r10.start() + 7 + s32(r10.group(1)) != key_end:
            continue
        lea = LEA_RDX.search(blob, r10.end(), r10.end() + 0x40)
        if not lea:
            continue
        data = lea.start() + 7 + s32(lea.group(1))
        end = lea.start() + 14 + s32(lea.group(2))
        return {"key": blob[k0:key_end], "data": data, "end": end}
    raise ValueError("stage 3 key not found")


def carve_pe(data: bytes) -> bytes:
    pe = pefile.PE(data=data, fast_load=True)
    end = max(
        [pe.OPTIONAL_HEADER.SizeOfHeaders]
        + [s.PointerToRawData + s.SizeOfRawData for s in pe.sections]
    )
    return data[:end]


def payload_info(pe_bytes: bytes) -> dict:
    out = {
        "sha256": hashlib.sha256(pe_bytes).hexdigest(),
        "size": len(pe_bytes),
    }
    pe = pefile.PE(data=pe_bytes)
    out["machine"] = hex(pe.FILE_HEADER.Machine)
    out["timestamp"] = pe.FILE_HEADER.TimeDateStamp
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        exp = pe.DIRECTORY_ENTRY_EXPORT
        name = pe.get_string_at_rva(exp.struct.Name)
        out["export_dll_name"] = name.decode("latin1") if name else None
        out["exports"] = [e.name.decode("latin1") for e in exp.symbols if e.name is not None]
    out["urls"] = sorted({u.decode("latin1") for u in URL.findall(pe_bytes)})
    return out


def unpack(path: str, outdir: str | None) -> dict:
    pe = pefile.PE(path)
    image = pe.get_memory_mapped_image()
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    rec: dict = {"file": path}
    with open(path, "rb") as fh:
        rec["sha256"] = hashlib.sha256(fh.read()).hexdigest()
    patch = entry_patch(image, ep)
    rec["entry_patch"] = {
        k: (hex(v) if k != "sleep_ms" and v is not None else v) for k, v in patch.items()
    }
    src = patch["copy_src_rva"]
    rec["carrier_resource"] = resource_of(pe, src)
    buf = bytearray(image[src : src + patch["copy_size"]])
    buf, s2off, wrapper = unwrap_stage2(buf, patch["stage2_offset"])
    if wrapper:
        rec["stage2_wrapper"] = wrapper
    s2 = stage2(buf, s2off, src)
    key_len, enc_len = s2["key_len"], s2["enc_len"]
    rec["stage2"] = {
        "key_png_len": key_len,
        "encrypted_len": enc_len,
        "stage3_entry": hex(s2["stage3_entry"]),
        "gates": s2["gates"],
    }
    key_png = bytes(buf[:key_len])
    plain = xor_repeat(bytes(buf[key_len : key_len + enc_len]), key_png)
    s3 = stage3(plain)
    rec["stage3"] = {
        "key": s3["key"].decode("latin1"),
        "key_hex": s3["key"].hex(),
        "payload_offset": hex(s3["data"]),
        "payload_end": hex(s3["end"]),
    }
    raw = xor_repeat(plain[s3["data"] : s3["end"]], s3["key"])
    if raw[:2] != b"MZ":
        raise ValueError("decrypted payload is not a PE")
    pe_bytes = carve_pe(raw)
    rec["payload"] = payload_info(pe_bytes)
    if outdir:
        os.makedirs(outdir, exist_ok=True)
        dest = os.path.join(outdir, rec["payload"]["sha256"])
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pe_bytes)
        rec["payload"]["written"] = dest
    return rec


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Unpack BubbleLoader-patched executables: entry-point patch, "
        "PNG-keyed stage 2, stage 3 XOR key, and the original payload PE "
        "(before the loader randomizes its int3 padding)."
    )
    ap.add_argument("files", nargs="+", help="patched host executables")
    ap.add_argument("-o", "--outdir", help="write decrypted payloads here (mode 600)")
    args = ap.parse_args()
    status = 0
    for f in args.files:
        try:
            rec = unpack(f, args.outdir)
        except Exception as exc:
            rec = {"file": f, "error": f"{type(exc).__name__}: {exc}"}
            status = 1
        print(json.dumps(rec))
    return status


if __name__ == "__main__":
    sys.exit(main())
