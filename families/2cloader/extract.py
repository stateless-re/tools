import argparse
import hashlib
import json
import struct
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

import pefile
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dissect.util.compression import lzxpress_huffman

CONFIG_SIZE = 0xDC
CONFIG_MAGIC = bytes.fromhex("2c3d4e5f")
CONFIG_FORMAT = "<5I12s16s16s16s5I4BI16s64sI16sIII"
CONFIG_FIELDS = (
    "magic",
    "execution_flags",
    "encrypted_size",
    "nonce_size",
    "tag_size",
    "nonce",
    "tag",
    "key_mask_low",
    "key_mask_high",
    "key_byte_sum",
    "persistence_flags",
    "option_flags",
    "dropped_file_size",
    "message_box_size",
    "xor2_step",
    "xor2_start",
    "xor1_start",
    "unknown_67",
    "sleep_ms",
    "build_id",
    "injection_target",
    "build_time",
    "payload_name",
    "unknown_d0",
    "task_interval_hours",
    "decompressed_size",
)
IMAGE_SCN_MEM_EXECUTE = 0x20000000


class ExtractionError(Exception):
    pass


@dataclass
class Result:
    file: str
    sha256: str
    resource: str
    config: dict
    key: str | None
    key_source: str | None
    payload_sha256: str | None
    payload_size: int | None
    payload_path: str | None


def find_config_resource(pe: pefile.PE) -> tuple[str, bytes]:
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        raise ExtractionError("no resource directory")
    for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if not hasattr(rtype, "directory"):
            continue
        for rname in rtype.directory.entries:
            if not hasattr(rname, "directory"):
                continue
            for rlang in rname.directory.entries:
                entry = rlang.data.struct
                data = pe.get_data(entry.OffsetToData, entry.Size)
                if len(data) > CONFIG_SIZE and data[-CONFIG_SIZE:][:4] == CONFIG_MAGIC:
                    label = f"{rtype.name or rtype.id}/{rname.name or rname.id}/{rlang.id}"
                    return label, data
    raise ExtractionError("no resource ends with a 2CLoader config")


def parse_config(blob: bytes) -> dict:
    values = struct.unpack(CONFIG_FORMAT, blob[-CONFIG_SIZE:])
    return dict(zip(CONFIG_FIELDS, values, strict=True))


def code_section(pe: pefile.PE) -> pefile.SectionStructure:
    for section in pe.sections:
        if section.Characteristics & IMAGE_SCN_MEM_EXECUTE:
            return section
    raise ExtractionError("no executable section")


def derive_key(digest: bytes, config: dict) -> bytes:
    low = bytes(a ^ b for a, b in zip(digest[:16], config["key_mask_low"], strict=True))
    high = bytes(a ^ b for a, b in zip(digest[16:], config["key_mask_high"], strict=True))
    return low + high


def find_key(pe: pefile.PE, config: dict) -> tuple[bytes, str]:
    section = code_section(pe)
    raw = section.get_data()
    candidates = (
        ("code section, virtual size", raw[: section.Misc_VirtualSize]),
        ("code section, raw size", raw),
    )
    for source, data in candidates:
        key = derive_key(hashlib.sha256(data).digest(), config)
        if sum(key) == config["key_byte_sum"]:
            return key, source
    raise ExtractionError("no key candidate matches the config's byte sum")


def remove_xor_layers(body: bytes, config: dict) -> bytes:
    start1, start2, step2 = config["xor1_start"], config["xor2_start"], config["xor2_step"]
    return bytes(
        b ^ ((start1 + i) & 0xFF) ^ ((start2 + i * step2) & 0xFF) for i, b in enumerate(body)
    )


def decrypt_payload(blob: bytes, config: dict, key: bytes) -> bytes:
    body = remove_xor_layers(blob[:-CONFIG_SIZE], config)
    try:
        compressed = AESGCM(key).decrypt(config["nonce"], body + config["tag"], None)
    except InvalidTag as exc:
        raise ExtractionError("AES-GCM authentication failed") from exc
    payload = lzxpress_huffman.decompress(compressed)[: config["decompressed_size"]]
    if len(payload) != config["decompressed_size"]:
        raise ExtractionError("decompressed payload is shorter than the config says")
    return payload


def printable_config(config: dict) -> dict:
    out = {}
    for name, value in config.items():
        if name in ("injection_target", "payload_name"):
            out[name] = value.split(b"\0", 1)[0].decode("latin-1")
        elif isinstance(value, bytes):
            out[name] = value.hex()
        elif name in ("magic", "execution_flags", "persistence_flags", "option_flags"):
            out[name] = f"{value:#x}"
        else:
            out[name] = value
    out["build_time_utc"] = datetime.fromtimestamp(config["build_time"], timezone.utc).isoformat()
    return out


def extract(path: Path, out_dir: Path | None) -> Result:
    data = path.read_bytes()
    pe = pefile.PE(data=data, fast_load=False)
    label, blob = find_config_resource(pe)
    config = parse_config(blob)
    result = Result(
        file=str(path),
        sha256=hashlib.sha256(data).hexdigest(),
        resource=label,
        config=printable_config(config),
        key=None,
        key_source=None,
        payload_sha256=None,
        payload_size=None,
        payload_path=None,
    )
    key, source = find_key(pe, config)
    result.key, result.key_source = key.hex(), source
    payload = decrypt_payload(blob, config, key)
    result.payload_sha256 = hashlib.sha256(payload).hexdigest()
    result.payload_size = len(payload)
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        target = out_dir / f"{result.payload_sha256}.bin"
        target.write_bytes(payload)
        target.chmod(0o600)
        result.payload_path = str(target)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extract the config of 2CLoader samples and decrypt their payload. "
        "Static only: nothing is executed."
    )
    parser.add_argument("files", nargs="+", type=Path, help="2CLoader executables")
    parser.add_argument(
        "-o",
        "--out-dir",
        type=Path,
        help="write decrypted payloads here, named by SHA-256 (not written by default)",
    )
    args = parser.parse_args(argv)
    status = 0
    for path in args.files:
        try:
            record = asdict(extract(path, args.out_dir))
        except (ExtractionError, pefile.PEFormatError, OSError) as exc:
            record = {"file": str(path), "error": str(exc)}
            status = 1
        print(json.dumps(record, indent=2))
    return status


if __name__ == "__main__":
    sys.exit(main())
