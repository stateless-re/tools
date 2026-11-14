import argparse
import base64
import binascii
import hashlib
import io
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from cryptography.hazmat.decrepit.ciphers.modes import CFB
except ImportError:
    from cryptography.hazmat.primitives.ciphers.modes import CFB
from cryptography.hazmat.primitives.padding import PKCS7

AOSP_TEST_PLATFORM_SHA1 = "27196e386b875e76adf700e7ea84e4c6eee33dfa"
CONFIG_CLASS = "Lx/cpe/util/EncryptUtils;"
TOPIC_CLASS = "Lx/cpe/mqtt/TopicAction;"
SDK_CONSTANTS_CLASS = "Lcom/ocean/zoe/acg/func/g;"
SDK_BUILD_CLASS = "Lcom/ocean/zoe/acg/func/e;"
SDK_RESOURCE = "com/ocean/zoe/letu.jet"
STRINGFOG_KEY = b"UTF-8"
CORE_CONSTANT_CLASSES = ("Lcom/sun/galaxy/lib/b;", "Lcom/sun/galaxy/lib/s;")
HOST_PATTERN = re.compile(r"[a-z0-9.-]*(anyevonline|szbboys|bestipip|100ulife)\.[a-z]+[^\s\"']*")


def quiet_androguard() -> None:
    from loguru import logger

    logger.remove()


def stringfog_decode(text: str) -> str:
    data = bytearray(base64.b64decode(text + "=" * (-len(text) % 4)))
    for index in range(len(data)):
        data[index] ^= STRINGFOG_KEY[index % len(STRINGFOG_KEY)]
    return data.decode("utf-8", "replace")


def xor_repeating(data: bytes, key: bytes) -> bytes:
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


def config_cipher(key: str) -> Cipher:
    raw = key.encode()
    return Cipher(algorithms.AES(raw), CFB(raw))


def decrypt_config(blob: str, key: str) -> str:
    decryptor = config_cipher(key).decryptor()
    plain = decryptor.update(base64.b64decode(blob)) + decryptor.finalize()
    return plain.decode("utf-8", "replace")


def encrypt_config(text: str, key: str) -> str:
    encryptor = config_cipher(key).encryptor()
    data = encryptor.update(text.encode()) + encryptor.finalize()
    return base64.b64encode(data).decode()


def decrypt_sdk(hex_text: str, key: str) -> str:
    decryptor = Cipher(algorithms.AES(key.encode()), modes.ECB()).decryptor()
    padded = decryptor.update(binascii.unhexlify(hex_text.strip())) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode("utf-8", "replace")


def static_values(dex: Any, class_name: str) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for cls in dex.get_classes():
        if cls.get_name() != class_name:
            continue
        for field in cls.get_fields():
            init = field.get_init_value()
            if init is not None:
                values[field.get_name()] = init.get_value()
    return values


def clinit_wrapped_strings(dex: Any, class_name: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for cls in dex.get_classes():
        if cls.get_name() != class_name:
            continue
        for method in cls.get_methods():
            if method.get_name() != "<clinit>" or method.get_code() is None:
                continue
            pending = None
            for ins in method.get_instructions():
                name = ins.get_name()
                operands = ins.get_output()
                if name.startswith("const-string"):
                    pending = operands.split(", ", 1)[1].strip().strip("'")
                elif name.startswith("sput-object") and pending is not None:
                    field = operands.split("->", 1)[1].split(" ", 1)[0]
                    found[field] = pending
                    pending = None
    return found


def dex_strings(dex: Any) -> list[str]:
    return [str(s) for s in dex.get_strings()]


def signer_info(apk: Any) -> list[dict[str, Any]]:
    result = []
    for cert in apk.get_certificates():
        sha1 = cert.sha1.hex()
        result.append(
            {
                "sha1": sha1,
                "subject": cert.subject.human_friendly,
                "not_before": cert["tbs_certificate"]["validity"]["not_before"].native.isoformat(),
                "aosp_test_platform_key": sha1 == AOSP_TEST_PLATFORM_SHA1,
            }
        )
    return result


def analyse_core_jar(data: bytes) -> dict[str, Any]:
    from androguard.core.dex import DEX

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        dex = DEX(archive.read("classes.dex"))
    constants: dict[str, Any] = {}
    for class_name in CORE_CONSTANT_CLASSES:
        constants.update({f"{class_name}{k}": v for k, v in static_values(dex, class_name).items()})
    strings = dex_strings(dex)
    return {
        "urls": sorted({s for s in strings if s.startswith("http") and "100ulife" in s}),
        "aes_key": next(
            (
                v
                for v in constants.values()
                if isinstance(v, str) and re.fullmatch(r"[0-9A-F]{32}", v)
            ),
            None,
        ),
        "entry_class": "com.sun.galaxy.lib.OceanInit"
        if "Lcom/sun/galaxy/lib/OceanInit;" in strings
        else None,
    }


def analyse_sdk(apk: Any, dexes: list[Any], out_dir: Path | None) -> dict[str, Any] | None:
    if SDK_RESOURCE not in apk.get_files():
        return None
    encoded: dict[str, str] = {}
    build: dict[str, Any] = {}
    for dex in dexes:
        encoded.update(clinit_wrapped_strings(dex, SDK_CONSTANTS_CLASS))
        build.update(static_values(dex, SDK_BUILD_CLASS))
    decoded = {name: stringfog_decode(value) for name, value in encoded.items()}
    resource_path = next((v for v in decoded.values() if v.endswith(".jet")), "/" + SDK_RESOURCE)
    xor_key = Path(resource_path).stem
    blob = apk.get_file(SDK_RESOURCE)
    jar = xor_repeating(blob, xor_key.encode())
    sdk: dict[str, Any] = {
        "resource": SDK_RESOURCE,
        "resource_sha256": hashlib.sha256(blob).hexdigest(),
        "xor_key": xor_key,
        "jar_sha256": hashlib.sha256(jar).hexdigest(),
        "jar_is_zip": jar[:4] == b"PK\x03\x04",
        "builtin_version": build.get("g"),
        "default_channel": build.get("f"),
        "stringfog": decoded,
    }
    if sdk["jar_is_zip"]:
        sdk["core"] = analyse_core_jar(jar)
        if out_dir is not None:
            out_dir.mkdir(parents=True, exist_ok=True)
            target = out_dir / sdk["jar_sha256"]
            target.write_bytes(jar)
            target.chmod(0o600)
            sdk["written"] = str(target)
    return sdk


def analyse_apk(path: Path, out_dir: Path | None) -> dict[str, Any]:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX

    apk = APK(str(path))
    dexes = [DEX(raw) for raw in apk.get_all_dex()]
    config: dict[str, Any] = {}
    topics: dict[str, Any] = {}
    strings: set[str] = set()
    for dex in dexes:
        config.update(static_values(dex, CONFIG_CLASS))
        topics.update(static_values(dex, TOPIC_CLASS))
        strings.update(dex_strings(dex))
    hosts = sorted({m.group(0) for s in strings if (m := HOST_PATTERN.search(s))})
    return {
        "file": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "package": apk.get_package(),
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "shared_user_id": apk.get_attribute_value("manifest", "sharedUserId"),
        "signers": signer_info(apk),
        "config_cipher": config.get("CIPHER_CFB_NOPADDING"),
        "config_key": config.get("KEY"),
        "hosts": hosts,
        "mqtt_topics": sorted(v.replace("/*/", "") for v in topics.values() if isinstance(v, str)),
        "sdk": analyse_sdk(apk, dexes, out_dir),
    }


def run_apk(args: argparse.Namespace) -> int:
    quiet_androguard()
    status = 0
    for path in args.files:
        try:
            record = analyse_apk(Path(path), Path(args.out) if args.out else None)
        except Exception as error:
            record = {"file": path, "error": f"{type(error).__name__}: {error}"}
            status = 1
        print(json.dumps(record, indent=2, ensure_ascii=False))
    return status


def run_text(args: argparse.Namespace) -> int:
    try:
        if args.mode == "config":
            payload = (
                json.loads(args.data).get("encryption", args.data)
                if args.data.lstrip().startswith("{")
                else args.data
            )
            text = decrypt_config(payload, args.key)
        elif args.mode == "config-encrypt":
            text = json.dumps({"encryption": encrypt_config(args.data, args.key)})
        else:
            text = decrypt_sdk(args.data, args.key)
        print(json.dumps({"mode": args.mode, "result": text}, ensure_ascii=False))
        return 0
    except Exception as error:
        print(json.dumps({"mode": args.mode, "error": f"{type(error).__name__}: {error}"}))
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Static extractor for x.cpe (XCPE botnet) APKs and their traffic."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    apk = sub.add_parser(
        "apk", help="report signer, config key, hosts, topics and the embedded MzSDK of x.cpe APKs"
    )
    apk.add_argument("files", nargs="+")
    apk.add_argument("-o", "--out", help="write the decrypted letu.jet core jar here")
    apk.set_defaults(func=run_apk)
    for mode, default_key, help_text in (
        (
            "config",
            "Iz4iWGbzcm2pHjSm",
            "decrypt an x.cpe /router/config body or its encryption field",
        ),
        (
            "config-encrypt",
            "Iz4iWGbzcm2pHjSm",
            "encrypt JSON the way x.cpe builds its request body",
        ),
        (
            "sdk",
            "DE252F9AC7624D723212E7E70972134D",
            "decrypt a dcsdk.100ulife.com hex response body",
        ),
    ):
        text = sub.add_parser(mode, help=help_text)
        text.add_argument("data")
        text.add_argument("--key", default=default_key)
        text.set_defaults(func=run_text, mode=mode)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
