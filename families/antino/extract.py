import argparse
import base64
import binascii
import hashlib
import json
import re
import struct
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import pefile

CONFIG_KEY = b"\xab\xcd"
CONFIG_SECTION = b".cfg"
SESSION_KEY = b"KxWNF"
JSON_START = bytes(a ^ b for a, b in zip(b'{"', CONFIG_KEY, strict=True))
MAX_CONFIG_LENGTH = 0x10000 - 4
MARKERS = {
    "antino_app_manifest": b'name="AntinoApp"',
    "rhai_engine": b"rhai-1.",
    "retour_hooks": b"retour-",
    "session_xor_key": SESSION_KEY,
    "thread_suspension_imports": b"Thread32First",
}


class ExtractionError(Exception):
    pass


@dataclass
class BuildInfo:
    machine: str | None = None
    timestamp: str | None = None
    pdb: str | None = None
    exports: list[str] = field(default_factory=list)
    markers: dict[str, bool] = field(default_factory=dict)


@dataclass
class Result:
    file: str
    sha256: str
    config_source: str | None = None
    config: dict | None = None
    build: BuildInfo | None = None
    error: str | None = None


def xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def decode_blob(blob: bytes, offset: int) -> dict | None:
    if offset + 4 > len(blob):
        return None
    (length,) = struct.unpack_from("<I", blob, offset)
    if not 2 <= length <= MAX_CONFIG_LENGTH or offset + 4 + length > len(blob):
        return None
    plain = xor(blob[offset + 4 : offset + 4 + length], CONFIG_KEY)
    try:
        value = json.loads(plain.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def config_from_section(pe: pefile.PE) -> tuple[str, dict] | None:
    for section in pe.sections:
        if section.Name.rstrip(b"\0") == CONFIG_SECTION:
            config = decode_blob(section.get_data(), 0)
            if config is not None:
                return f".cfg section at file offset {section.PointerToRawData:#x}", config
    return None


def config_from_scan(data: bytes) -> tuple[str, dict] | None:
    for match in re.finditer(re.escape(JSON_START), data):
        offset = match.start() - 4
        if offset < 0:
            continue
        config = decode_blob(data, offset)
        if config is not None and "tenant_id" in config:
            return f"scan at file offset {offset:#x}", config
    return None


def redact(config: dict) -> dict:
    secret = config.get("client_secret")
    if isinstance(secret, str):
        return {**config, "client_secret": f"<redacted, {len(secret)} chars>"}
    return config


def build_info(pe: pefile.PE | None, data: bytes) -> BuildInfo:
    info = BuildInfo(markers={name: marker in data for name, marker in MARKERS.items()})
    if pe is None:
        return info
    info.machine = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
    stamp = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, tz=timezone.utc)
    info.timestamp = stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    pe.parse_data_directories(
        directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        ]
    )
    for entry in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        name = getattr(entry.entry, "PdbFileName", None)
        if name:
            info.pdb = name.rstrip(b"\0").decode("utf-8", "replace")
    export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if export_dir is not None:
        info.exports = [s.name.decode() for s in export_dir.symbols if s.name]
    return info


def extract(path: Path, show_secret: bool) -> Result:
    data = path.read_bytes()
    result = Result(file=str(path), sha256=hashlib.sha256(data).hexdigest())
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError:
        pe = None
    found = (config_from_section(pe) if pe is not None else None) or config_from_scan(data)
    result.build = build_info(pe, data)
    if found is None:
        result.error = "no Antino configuration found"
        return result
    result.config_source, config = found
    result.config = config if show_secret else redact(config)
    return result


def decode_session(value: str) -> dict:
    try:
        raw = base64.b64decode(value, validate=True)
    except binascii.Error as exc:
        return {"session_id": value, "error": f"not base64: {exc}"}
    text = xor(raw, SESSION_KEY).decode("utf-8", "replace")
    parts = text.split(":", 4)
    if len(parts) != 5:
        return {"session_id": value, "decoded": text, "error": "expected 5 fields"}
    keys = ("process_id", "machine_name", "username", "platform", "fifth_field")
    return {"session_id": value, **dict(zip(keys, parts, strict=True))}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract Antino backdoor configuration (.cfg section, XOR AB CD) from "
        "EXE/DLL builds or memory dumps, or decode Gen1 session IDs."
    )
    parser.add_argument("files", nargs="*", type=Path, help="Antino samples or memory dumps")
    parser.add_argument(
        "--show-secret",
        action="store_true",
        help="print client_secret in full (redacted by default)",
    )
    parser.add_argument(
        "--session",
        action="append",
        default=[],
        metavar="ID",
        help="decode a Gen1 session ID (Base64 of XOR 'KxWNF'); repeatable",
    )
    args = parser.parse_args()
    if not args.files and not args.session:
        parser.error("give at least one file or --session")
    failed = False
    records: list[dict] = []
    for path in args.files:
        try:
            result = extract(path, args.show_secret)
        except (OSError, ExtractionError) as exc:
            result = Result(file=str(path), sha256="", error=str(exc))
        failed |= result.error is not None
        records.append(asdict(result))
    for value in args.session:
        decoded = decode_session(value)
        failed |= "error" in decoded
        records.append(decoded)
    json.dump(records, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
