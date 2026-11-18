import argparse
import base64
import bisect
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PCLN_MAGICS = (b"\xf0\xff\xff\xff\x00\x00\x01\x08", b"\xf1\xff\xff\xff\x00\x00\x01\x08")
BUILDINFO_MAGIC = b"\xff Go buildinf:"
HEAD_FIELDS = (
    "server",
    "server_is_raw_list",
    "solana_enabled",
    "solana_address",
    "solana_rpc_endpoints",
    "agent_token",
)
BLOCK_FIELDS = ("persistence", "critical_process")
BOOL_VALUES = {"true", "false", "1", "0", "yes", "no", ""}
SEMVER = re.compile(r"\d+\.\d+\.\d+")
RIP = re.compile(r"\[rip ([+-]) (0x[0-9a-f]+)\]")
IMM = re.compile(r", (0x[0-9a-f]+|\d+)$")
ENV_NAME = re.compile(rb"[A-Z][A-Z0-9_]{3,62}")


class Image:
    def __init__(self, path: Path):
        self.data = path.read_bytes()
        self.pe = pefile.PE(data=self.data, fast_load=True)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.img = self.pe.get_memory_mapped_image()
        self.funcs = self.load_functions()
        self.addrs = [a for a, _ in self.funcs]
        self.names = dict(self.funcs)

    def read(self, va: int, size: int) -> bytes:
        off = va - self.base
        if off < 0 or off + size > len(self.img):
            return b""
        return self.img[off : off + size]

    def string_at(self, header_va: int) -> str | None:
        raw = self.read(header_va, 16)
        if len(raw) < 16:
            return None
        ptr, size = struct.unpack("<QQ", raw)
        if ptr == 0 and size == 0:
            return ""
        if not 0 < size < 65536:
            return None
        body = self.read(ptr, size)
        return body.decode("utf-8", "replace") if len(body) == size else None

    def pclntab_offset(self) -> int:
        for magic in PCLN_MAGICS:
            off = self.data.find(magic)
            if off >= 0:
                return off
        raise ValueError("no Go pclntab found")

    def text_base(self, tab_off: int) -> int:
        tab_va = self.base + self.pe.get_rva_from_offset(tab_off)
        needle = struct.pack("<Q", tab_va)
        pos = self.img.find(needle)
        while pos >= 0:
            if pos % 8 == 0 and pos + 184 <= len(self.img):
                minpc, maxpc, text = struct.unpack_from("<QQQ", self.img, pos + 160)
                if self.base <= text <= minpc < maxpc < self.base + len(self.img):
                    return text
            pos = self.img.find(needle, pos + 1)
        raise ValueError("Go moduledata not found")

    def load_functions(self) -> list[tuple[int, str]]:
        off = self.pclntab_offset()
        nfunc, _, text_start, name_off, _, _, _, pcln_off = struct.unpack_from(
            "<8Q", self.data, off + 8
        )
        base = text_start or self.text_base(off)
        table = self.data[off:]
        out = []
        for index in range(nfunc):
            entry, func_off = struct.unpack_from("<II", table, pcln_off + index * 8)
            rel = struct.unpack_from("<i", table, pcln_off + func_off + 4)[0]
            start = name_off + rel
            name = table[start : table.index(b"\0", start)].decode("utf-8", "replace")
            out.append((base + entry, name))
        return sorted(out)

    def function(self, suffix: str) -> tuple[int, int, str] | None:
        for index, (addr, name) in enumerate(self.funcs[:-1]):
            if name.endswith(suffix):
                return addr, self.funcs[index + 1][0], name
        return None

    def callee(self, target: int) -> str:
        index = bisect.bisect_right(self.addrs, target) - 1
        return self.names[self.addrs[index]] if index >= 0 else ""


def rip_target(insn) -> int | None:
    match = RIP.search(insn.op_str)
    if not match:
        return None
    disp = int(match.group(2), 16)
    return insn.address + insn.size + (disp if match.group(1) == "+" else -disp)


def events(image: Image, start: int, end: int) -> list[tuple[str, object]]:
    insns = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(image.read(start, end - start), start))
    out: list[tuple[str, object]] = []
    for index, insn in enumerate(insns):
        target = rip_target(insn)
        if insn.mnemonic == "lea" and target:
            env = env_name(image, target, insns[index + 1 : index + 4])
            if env:
                out.append(("env", env))
        elif (
            insn.mnemonic == "mov"
            and target
            and "qword ptr [rip" in insn.op_str
            and not insn.op_str.startswith("qword")
        ):
            if index + 1 < len(insns) and rip_target(insns[index + 1]) == target + 8:
                value = image.string_at(target)
                if value is not None:
                    out.append(("var", (target, value)))
        elif insn.mnemonic == "call" and insn.op_str.startswith("0x"):
            out.append(("call", image.callee(int(insn.op_str, 16))))
    return out


def env_name(image: Image, target: int, following) -> str | None:
    for insn in following:
        match = IMM.search(insn.op_str)
        if insn.mnemonic == "mov" and match:
            size = int(match.group(1), 0)
            raw = image.read(target, size)
            return raw.decode() if 0 < size < 64 and ENV_NAME.fullmatch(raw) else None
    return None


def assign_config(evts: list[tuple[str, object]]) -> dict:
    loads = [payload for kind, payload in evts if kind == "var"]
    if len(loads) < 7:
        raise ValueError("config.Load reads too few build-time strings")
    config: dict = {}
    for field, (_, value) in zip(HEAD_FIELDS, loads, strict=False):
        config[field] = value
    token_addr = loads[5][0]
    second = next((i for i in range(6, len(loads)) if loads[i][0] == token_addr), None)
    if second is None:
        raise ValueError("second agent token read not found")
    block = loads[6:second]
    for field, (_, value) in zip(BLOCK_FIELDS, block, strict=False):
        config[field] = value
    for _, value in block[2:]:
        key = (
            "fetch_public_ip"
            if value.lower() in BOOL_VALUES and "fetch_public_ip" not in config
            else "tls_spki_pins"
        )
        config[key] = value
    tail = loads[second + 1 :]
    if tail:
        config["mutex"] = tail[0][1]
    assign_tail(config, tail[1:], evts)
    return config


def assign_tail(config: dict, tail: list[tuple[int, str]], evts: list[tuple[str, object]]) -> None:
    sleep_addr = None
    last_var = None
    for kind, payload in evts:
        if kind == "var":
            last_var = payload
        elif kind == "call" and str(payload).endswith("config.parseSleepSeconds") and last_var:
            sleep_addr = last_var[0]
    rest = []
    for addr, value in tail:
        if addr == sleep_addr:
            config["sleep_seconds"] = value
        elif SEMVER.fullmatch(value) and "agent_version" not in config:
            config["agent_version"] = value
        else:
            rest.append(value)
    if rest:
        config["build_tag"] = rest[-1]
    if len(rest) > 1:
        config["country"] = rest[0]


def env_overrides(evts: list[tuple[str, object]]) -> list[str]:
    return sorted(
        {
            str(payload)
            for kind, payload in evts
            if kind == "env" and str(payload).startswith("OVERLORD_")
        }
    )


def startup_name(image: Image) -> str | None:
    found = image.function("/cmd/agent/persistence.generateBinaryName")
    if not found:
        return None
    start, end, _ = found
    for insn in Cs(CS_ARCH_X86, CS_MODE_64).disasm(image.read(start, end - start), start):
        target = rip_target(insn)
        if (
            insn.mnemonic == "mov"
            and target
            and "qword ptr [rip" in insn.op_str
            and not insn.op_str.startswith("qword")
        ):
            for header in (target, target - 8):
                value = image.string_at(header)
                if value:
                    return value
            return ""
    return None


def read_uvarint(data: bytes, pos: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, pos
        shift += 7


def build_info(image: Image) -> dict:
    pos = image.data.find(BUILDINFO_MAGIC)
    if pos < 0 or not image.data[pos + 15] & 2:
        return {}
    size, cur = read_uvarint(image.data, pos + 32)
    version = image.data[cur : cur + size].decode("utf-8", "replace")
    size, cur = read_uvarint(image.data, cur + size)
    modinfo = image.data[cur : cur + size].decode("utf-8", "replace")
    info = {"go_version": version}
    for line in modinfo.splitlines():
        parts = line.split("\t")
        if parts[0] == "path" and len(parts) > 1:
            info["module_path"] = parts[1]
        elif parts[0] == "build" and len(parts) > 1 and parts[1].startswith("-tags="):
            info["build_tags"] = parts[1][6:].split(",")
    return info


def decode_build_tag(tag: str) -> object:
    payload = tag.split(".", 1)[0]
    try:
        decoded = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (ValueError, json.JSONDecodeError):
        return None
    return decoded if isinstance(decoded, dict) else None


def decrypt_memo(memo: str, token: str) -> str:
    try:
        raw = base64.b64decode(memo, validate=True)
    except ValueError:
        raw = base64.urlsafe_b64decode(memo + "=" * (-len(memo) % 4))
    key = hashlib.sha256(token.encode()).digest()
    return AESGCM(key).decrypt(raw[:12], raw[12:], None).decode("utf-8", "replace")


def analyze(path: Path, memos: list[str]) -> dict:
    data = path.read_bytes()
    record: dict = {"file": str(path), "sha256": hashlib.sha256(data).hexdigest()}
    try:
        image = Image(path)
        found = image.function("/cmd/agent/config.Load")
        if not found:
            raise ValueError(
                "no */cmd/agent/config.Load: not an Overlord agent, or names are obfuscated"
            )
        evts = events(image, found[0], found[1])
        config = assign_config(evts)
        name = startup_name(image)
        if name is not None:
            config["startup_name"] = name
        config["memo_key_sha256_of_token"] = hashlib.sha256(
            config["agent_token"].encode()
        ).hexdigest()
        decoded = decode_build_tag(config.get("build_tag", ""))
        if decoded is not None:
            config["build_tag_decoded"] = decoded
        record.update(build_info(image))
        record["package"] = found[2].rsplit("/config.Load", 1)[0]
        record["gui_subsystem"] = image.pe.OPTIONAL_HEADER.Subsystem == 2
        record["config"] = config
        record["env_overrides"] = env_overrides(evts)
        if memos:
            record["memos"] = [memo_result(memo, config["agent_token"]) for memo in memos]
    except Exception as exc:
        record["error"] = str(exc)
    return record


def memo_result(memo: str, token: str) -> dict:
    try:
        return {"memo": memo, "plaintext": decrypt_memo(memo, token)}
    except Exception as exc:
        return {"memo": memo, "error": str(exc) or type(exc).__name__}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Overlord RAT Windows agent build-time config (Go -X strings).",
    )
    parser.add_argument("files", nargs="+", type=Path, help="Overlord agent executables")
    parser.add_argument(
        "--memo",
        action="append",
        default=[],
        help="base64 Solana memo to decrypt with each file's agent token (repeatable)",
    )
    args = parser.parse_args()
    results = [analyze(path, args.memo) for path in args.files]
    print(json.dumps(results, indent=2, ensure_ascii=False))
    return 1 if any("error" in r for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
