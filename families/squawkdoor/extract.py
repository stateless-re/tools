import argparse
import hashlib
import json
import os
import re
import struct
import sys
import zlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import olefile
import pefile

DEFAULT_KEY = b"Hg5th5324Ve"
SHELLCODE_PROLOGUE = bytes.fromhex("558bec64a130000000")
IMAGE_OFFSET = 0x400
CONFIG_SIZES = {0x61: "v1", 0x63: "v2"}
MUTEX_MARKER = b"squadc_single_instance"


class ExtractionError(Exception):
    pass


@dataclass
class Config:
    source: str
    image_sha256: str
    image_timestamp: str
    config_version: str
    config_size: int
    c2: str
    magic_tag: str
    ping_url: str
    beacon_interval_minutes: int
    need_browser_waiting: int | None
    anti_analysis_enabled: int | None


@dataclass
class Result:
    file: str
    sha256: str
    configs: list[Config] = field(default_factory=list)
    error: str | None = None


def rc4(key: bytes, data: bytes) -> bytes:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    out = bytearray(len(data))
    i = j = 0
    for n, byte in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        out[n] = byte ^ state[(state[i] + state[j]) & 0xFF]
    return bytes(out)


def cstring(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("latin-1")


def mszip_folder(cab: bytes, data_offset: int, block_count: int, reserve: int) -> bytes:
    out = bytearray()
    window = b""
    pos = data_offset
    for _ in range(block_count):
        compressed_size, _uncompressed_size = struct.unpack_from("<HH", cab, pos + 4)
        block = cab[pos + 8 + reserve : pos + 8 + reserve + compressed_size]
        pos += 8 + reserve + compressed_size
        if block[:2] != b"CK":
            raise ExtractionError("MSZIP block without CK signature")
        inflater = zlib.decompressobj(-15, zdict=window) if window else zlib.decompressobj(-15)
        chunk = inflater.decompress(block[2:]) + inflater.flush()
        out += chunk
        window = bytes(out[-32768:])
    return bytes(out)


def cab_files(cab: bytes) -> dict[str, bytes]:
    if cab[:4] != b"MSCF":
        raise ExtractionError("not a cabinet")
    files_offset = struct.unpack_from("<I", cab, 16)[0]
    folder_count, file_count, flags = struct.unpack_from("<HHH", cab, 26)
    pos = 36
    folder_reserve = data_reserve = 0
    if flags & 4:
        header_reserve, folder_reserve, data_reserve = struct.unpack_from("<HBB", cab, pos)
        pos += 4 + header_reserve
    folders = []
    for _ in range(folder_count):
        data_offset, block_count, compression = struct.unpack_from("<IHH", cab, pos)
        pos += 8 + folder_reserve
        if compression & 0xF not in (0, 1):
            raise ExtractionError(f"unsupported cabinet compression {compression}")
        folders.append((data_offset, block_count, compression & 0xF))
    unpacked = []
    for data_offset, block_count, compression in folders:
        if compression == 1:
            unpacked.append(mszip_folder(cab, data_offset, block_count, data_reserve))
        else:
            unpacked.append(raw_folder(cab, data_offset, block_count, data_reserve))
    result = {}
    pos = files_offset
    for _ in range(file_count):
        size, offset, folder_index = struct.unpack_from("<IIH", cab, pos)
        name_end = cab.index(b"\0", pos + 16)
        name = cab[pos + 16 : name_end].decode("latin-1")
        pos = name_end + 1
        result[name] = unpacked[folder_index][offset : offset + size]
    return result


def raw_folder(cab: bytes, data_offset: int, block_count: int, reserve: int) -> bytes:
    out = bytearray()
    pos = data_offset
    for _ in range(block_count):
        compressed_size = struct.unpack_from("<H", cab, pos + 4)[0]
        out += cab[pos + 8 + reserve : pos + 8 + reserve + compressed_size]
        pos += 8 + reserve + compressed_size
    return bytes(out)


def msi_payloads(path: Path) -> dict[str, bytes]:
    found: dict[str, bytes] = {}
    with olefile.OleFileIO(str(path)) as ole:
        for entry in ole.listdir(streams=True, storages=False):
            stream = ole.openstream(entry).read()
            if stream[:4] == b"MSCF":
                found.update(cab_files(stream))
    if not found:
        raise ExtractionError("no cabinet stream in MSI")
    return found


def restore_image(stage2: bytes) -> bytes:
    image = bytearray(stage2[IMAGE_OFFSET:])
    if len(image) < 0x400:
        raise ExtractionError("stage 2 too short for an embedded image")
    e_lfanew = struct.unpack_from("<I", image, 0x3C)[0]
    if e_lfanew + 0x18 > len(image):
        raise ExtractionError("embedded image has an invalid e_lfanew")
    image[0:2] = b"MZ"
    image[e_lfanew : e_lfanew + 4] = b"PE\0\0"
    pe = pefile.PE(data=bytes(image), fast_load=True)
    end = max(s.PointerToRawData + s.SizeOfRawData for s in pe.sections)
    return bytes(image[:end])


def to_image(data: bytes, key: bytes) -> bytes | None:
    if data[:2] == b"MZ" and MUTEX_MARKER in data:
        return data
    if data[: len(SHELLCODE_PROLOGUE)] == SHELLCODE_PROLOGUE:
        return restore_image(data)
    head = rc4(key, data[: len(SHELLCODE_PROLOGUE)])
    if head == SHELLCODE_PROLOGUE:
        return restore_image(rc4(key, data))
    return None


def config_size(image: bytes, data_va: int) -> int:
    pattern = re.compile(
        rb"\xb9([\x61\x63])\x00\x00\x00.{0,12}?\xbe" + re.escape(struct.pack("<I", data_va)), re.S
    )
    match = pattern.search(image)
    if not match:
        raise ExtractionError("config copy (mov ecx, N / mov esi, .data) not found")
    return match.group(1)[0]


def parse_image(image: bytes, key: bytes, source: str) -> Config:
    pe = pefile.PE(data=image)
    data = next((s for s in pe.sections if s.Name.rstrip(b"\0") == b".data"), None)
    if data is None:
        raise ExtractionError("image has no .data section")
    data_va = pe.OPTIONAL_HEADER.ImageBase + data.VirtualAddress
    dwords = config_size(image, data_va)
    size = dwords * 4
    mapped = pe.get_memory_mapped_image()
    config = rc4(key, mapped[data.VirtualAddress : data.VirtualAddress + size])
    interval = struct.unpack_from("<I", config, 0x180)[0]
    browser = anti = None
    if size >= 0x18C:
        browser, anti = struct.unpack_from("<II", config, 0x184)
    stamp = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, tz=timezone.utc)
    return Config(
        source=source,
        image_sha256=hashlib.sha256(image).hexdigest(),
        image_timestamp=stamp.strftime("%Y-%m-%d %H:%M:%S"),
        config_version=CONFIG_SIZES[dwords],
        config_size=size,
        c2=cstring(config[0x00:0x40]),
        magic_tag=cstring(config[0x40:0x80]),
        ping_url=cstring(config[0x80:0x180]),
        beacon_interval_minutes=interval,
        need_browser_waiting=browser,
        anti_analysis_enabled=anti,
    )


def write_image(image: bytes, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{hashlib.sha256(image).hexdigest()}.bin"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(image)


def candidates(path: Path, data: bytes) -> dict[str, bytes]:
    if data[:8] == bytes.fromhex("d0cf11e0a1b11ae1"):
        return msi_payloads(path)
    return {path.name: data}


def extract(path: Path, key: bytes, out_dir: Path | None) -> Result:
    data = path.read_bytes()
    result = Result(file=str(path), sha256=hashlib.sha256(data).hexdigest())
    for name, blob in candidates(path, data).items():
        image = to_image(blob, key)
        if image is None:
            continue
        result.configs.append(parse_image(image, key, name))
        if out_dir is not None:
            write_image(image, out_dir)
    if not result.configs:
        raise ExtractionError("no SquawkDoor payload found (wrong key or not SquawkDoor)")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract the SquawkDoor (SquadC) configuration from MSI installers, "
        "encrypted payload files, decrypted stage 2 blobs or carved images."
    )
    parser.add_argument("files", nargs="+", type=Path, help="MSI, payload or image files")
    parser.add_argument(
        "--key", default=DEFAULT_KEY.decode(), help="RC4 key (default: %(default)s)"
    )
    parser.add_argument("-o", "--out", type=Path, help="write restored images to this directory")
    args = parser.parse_args()
    key = args.key.encode()
    results = []
    failed = False
    for path in args.files:
        try:
            results.append(extract(path, key, args.out))
        except (OSError, ValueError, struct.error, pefile.PEFormatError, ExtractionError) as error:
            failed = True
            results.append(Result(file=str(path), sha256="", error=str(error)))
    print(json.dumps([asdict(r) for r in results], indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
