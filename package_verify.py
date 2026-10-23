#!/usr/bin/env python3
"""Host-only validation of a Frameo SD artifact; never executes its payload."""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
from zipfile import BadZipFile, ZipFile

SCHEMA = "frameo-jailbreak-sd/v1"
PACKAGE = "net.frameo.frame"
PAYLOAD_NAME = "x';sh${IFS}$(find${IFS}${ANDROID_DATA%data}storage${IFS}-maxdepth${IFS}2${IFS}-name${IFS}p_frameo_jb);#.apk"
CONFIG_BODY = b"auto_run=action_update_version\n"
OUTPUTS = {"sd_zip": "frameo-jailbreak-sd.zip", "sd_dir": "sd", "connect_script": "connect.sh"}
SD_FILES = {"Frameo_utilities/frameo_utilities.config", "Frameo_utilities/" + PAYLOAD_NAME,
            "p_frameo_jb", "adbkey"}
MANIFEST_FILES = {"sd/" + name for name in SD_FILES} | {"connect.sh", "frameo-jailbreak-sd.zip"}


class VerificationError(ValueError):
    pass


def fail(message: str) -> None:
    raise VerificationError(message)


def validate_adb_blob(blob: str) -> None:
    """Decode Android's RSAPublicKey struct and validate its RSA parameters."""
    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        fail("ADB public key is not valid base64")
    if len(raw) != 524 or base64.b64encode(raw).decode("ascii") != blob:
        fail("ADB public key must contain the 524-byte Android RSA public-key structure")
    words, n0inv = struct.unpack_from("<II", raw)
    modulus = int.from_bytes(raw[8:264], "little")
    rr = int.from_bytes(raw[264:520], "little")
    exponent, = struct.unpack_from("<I", raw, 520)
    if words != 64 or modulus.bit_length() != 2048 or modulus % 2 != 1:
        fail("ADB public key has invalid RSA-2048 modulus/word count")
    if exponent not in (3, 65537):
        fail("ADB public key has an unsupported RSA exponent")
    if (modulus * n0inv) % (1 << 32) != (1 << 32) - 1:
        fail("ADB public key has invalid Montgomery inverse")
    if rr != pow(2, 4096, modulus):
        fail("ADB public key has invalid Montgomery R-squared value")


def read_json(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        fail(f"manifest is not a regular file: {path}")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                fail(f"duplicate JSON key: {key}")
            result[key] = value
        return result
    try:
        obj = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"cannot read manifest: {exc}")
    if not isinstance(obj, dict):
        fail("manifest must be a JSON object")
    return obj


def assert_no_symlink_components(path: Path) -> Path:
    """Inspect the lexical path before resolve() can hide a symlink."""
    lexical = path.expanduser()
    if not lexical.is_absolute():
        lexical = Path.cwd() / lexical
    part = Path(lexical.anchor)
    for component in lexical.parts[1:]:
        part /= component
        if part.is_symlink():
            fail(f"symlink path component is not allowed: {part}")
    return Path(os.path.abspath(lexical))


def usable_tool(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def version_key(path: Path) -> tuple:
    return tuple((0, int(x)) if x.isdigit() else (1, x) for x in re.split(r"[.-]", path.name))


def find_aapt2(build_tools: Path | str | None = None, sdk: Path | str | None = None) -> Path:
    if build_tools:
        tool = Path(build_tools).expanduser() / "aapt2"
        if not all(usable_tool(tool.parent / name) for name in ("aapt2", "apksigner")):
            fail(f"aapt2/apksigner missing or not executable: {tool.parent}")
        return tool.resolve()
    if sdk:
        candidates = [Path(sdk).expanduser()]
    else:
        candidates = [Path(value).expanduser() for value in (
            os.environ.get("ANDROID_SDK_ROOT"), os.environ.get("ANDROID_HOME"),
            str(Path.home() / "Library/Android/sdk"), str(Path.home() / "Android/Sdk")) if value]
    for root in candidates:
        versions = [p for p in (root / "build-tools").glob("*")
                    if all(usable_tool(p / name) for name in ("aapt2", "apksigner"))]
        if versions:
            return (sorted(versions, key=version_key)[-1] / "aapt2").resolve()
    fail("aapt2/apksigner not found in the current Android SDK; pass --build-tools or --android-sdk")


def validate_manifest(manifest: dict) -> None:
    if manifest.get("schema") != SCHEMA or manifest.get("outputs") != OUTPUTS:
        fail("unrecognized manifest schema/output layout")
    target = manifest.get("target", {})
    payload = manifest.get("payload", {})
    if not isinstance(target, dict) or target.get("package") != PACKAGE or target.get("frameo_version_code") != 69880:
        fail("manifest target identity mismatch")
    if not isinstance(payload, dict) or payload.get("filename") != PAYLOAD_NAME:
        fail("unexpected payload filename")
    if payload.get("script") != "p_frameo_jb" or payload.get("config") != CONFIG_BODY.decode().strip():
        fail("unexpected payload script/config metadata")
    if payload.get("adb_key_comment") != "frameo-jailbreak" or payload.get("version_name") != "1.30.20":
        fail("unexpected payload key/version metadata")
    version_code = str(payload.get("version_code", ""))
    if not re.fullmatch(r"[0-9]+", version_code) or not 69880 < int(version_code) <= 2100000000:
        fail("invalid payload version code")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != MANIFEST_FILES:
        fail("manifest file inventory differs from the SD package layout")
    for name, info in files.items():
        if (not isinstance(info, dict) or set(info) != {"bytes", "sha256"}
                or type(info.get("bytes")) is not int or info["bytes"] < 0
                or not isinstance(info.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", info["sha256"])):
            fail(f"invalid manifest hash/size metadata: {name}")
    apk_info = files["sd/Frameo_utilities/" + PAYLOAD_NAME]
    if payload.get("apk_sha256") != apk_info["sha256"]:
        fail("payload APK hash differs from manifest file hash")


def verify_package(out: Path | str, *, build_tools: Path | str | None = None,
                   sdk: Path | str | None = None, aapt2: Path | None = None) -> dict:
    out = assert_no_symlink_components(Path(out))
    if not out.is_dir():
        fail(f"output directory is missing: {out}")
    for path in out.rglob("*"):
        if path.is_symlink():
            fail(f"symlink is not allowed in an artifact: {path.relative_to(out)}")
    manifest = read_json(out / "manifest.json")
    validate_manifest(manifest)
    sd = out / "sd"
    if not sd.is_dir():
        fail("missing sd directory")
    actual_files, actual_dirs = set(), set()
    for path in sd.rglob("*"):
        rel = path.relative_to(sd).as_posix()
        if path.is_symlink():
            fail(f"symlink is not allowed on the SD card: {rel}")
        if path.is_dir():
            actual_dirs.add(rel)
        elif path.is_file():
            actual_files.add(rel)
        else:
            fail(f"special file is not allowed on the SD card: {rel}")
    if actual_files != SD_FILES or actual_dirs != {"Frameo_utilities"}:
        fail(f"SD inventory differs: unexpected={sorted((actual_files - SD_FILES) | (actual_dirs - {'Frameo_utilities'}))}, missing={sorted(SD_FILES - actual_files)}")
    for name, info in manifest["files"].items():
        path = out / name
        if not path.is_file():
            fail(f"manifest file missing: {name}")
        data = path.read_bytes()
        if len(data) != info["bytes"] or hashlib.sha256(data).hexdigest() != info["sha256"]:
            fail(f"hash/size mismatch: {name}")
    if (sd / "Frameo_utilities/frameo_utilities.config").read_bytes() != CONFIG_BODY:
        fail("unexpected config body")
    try:
        key = (sd / "adbkey").read_text(encoding="utf-8")
    except UnicodeError:
        fail("adbkey is not UTF-8")
    if not re.fullmatch(r"[^\s]+ frameo-jailbreak\n", key):
        fail("adbkey must be one Android public key with the frameo-jailbreak comment")
    validate_adb_blob(key.split()[0])
    try:
        with ZipFile(out / "frameo-jailbreak-sd.zip") as zf:
            entries = zf.infolist()
            names = [entry.filename for entry in entries]
            if len(names) != len(set(names)):
                fail("ZIP contains duplicate entries")
            if set(names) != SD_FILES:
                fail("ZIP inventory differs from the SD package layout")
            for entry in entries:
                mode = entry.external_attr >> 16
                if (entry.orig_filename != entry.filename or entry.is_dir() or stat.S_ISLNK(mode)
                        or stat.S_IFMT(mode) not in (0, stat.S_IFREG)):
                    fail(f"ZIP entry is not a regular file: {entry.filename}")
                if zf.read(entry) != (sd / entry.filename).read_bytes():
                    fail(f"ZIP bytes differ from SD/manifest: {entry.filename}")
    except (BadZipFile, RuntimeError, NotImplementedError) as exc:
        fail(f"invalid ZIP: {exc}")
    payload_path = sd / "Frameo_utilities" / PAYLOAD_NAME
    verify_payload_apk(payload_path, manifest, build_tools=build_tools, sdk=sdk, aapt2=aapt2)
    return manifest


def verify_payload_apk(payload_path: Path | str, manifest: dict, *,
                       build_tools: Path | str | None = None,
                       sdk: Path | str | None = None,
                       aapt2: Path | None = None) -> None:
    payload_path = Path(payload_path)
    tool = aapt2 or find_aapt2(build_tools, sdk)
    try:
        proc = subprocess.run([str(tool), "dump", "badging", str(payload_path)],
                              check=True, text=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"aapt2 failed to inspect payload APK: {exc}")
    match = re.search(r"package: name='([^']+)' versionCode='([^']+)' versionName='([^']*)'", proc.stdout)
    expected = (PACKAGE, str(manifest["payload"]["version_code"]), manifest["payload"]["version_name"])
    if not match or match.groups() != expected:
        fail("APK package/version mismatch")
    signer = tool.parent / "apksigner"
    if not usable_tool(signer):
        fail(f"apksigner missing or not executable: {signer}")
    try:
        subprocess.run([str(signer), "verify", str(payload_path)],
                       check=True, text=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"APK signature verification failed: {exc}")


def verify_sd_card(card: Path | str, source_sd: Path | str, manifest: dict, *,
                   build_tools: Path | str | None = None,
                   sdk: Path | str | None = None,
                   aapt2: Path | None = None) -> None:
    """Verify the actual mounted-card files after an SD write."""
    card = assert_no_symlink_components(Path(card))
    if not card.is_dir():
        fail(f"card path is not a directory: {card}")
    source_sd = Path(source_sd)
    if not source_sd.is_dir():
        fail(f"source SD directory is missing: {source_sd}")
    validate_manifest(manifest)
    frameo = card / "Frameo_utilities"
    if not frameo.is_dir() or frameo.is_symlink():
        fail("card is missing Frameo_utilities")
    actual = set()
    for path in frameo.rglob("*"):
        rel = path.relative_to(frameo).as_posix()
        if path.is_symlink() or path.is_dir():
            fail(f"unexpected directory/symlink on card: {rel}")
        actual.add(rel)
    expected_frameo = {"frameo_utilities.config", PAYLOAD_NAME}
    if actual != expected_frameo:
        fail(f"card Frameo_utilities inventory differs: {sorted(actual)}")
    for rel in ("p_frameo_jb", "adbkey"):
        path = card / rel
        if path.is_symlink() or not path.is_file():
            fail(f"card missing regular file: {rel}")
    for forbidden in ("README.txt", "started", "done", "result.txt",
                      "adb_keys.before", "adb_keys.before.state",
                      "connect.sh", "frameo-jailbreak-sd.zip", "manifest.json"):
        if (card / forbidden).exists():
            fail(f"unexpected package artifact on card: {forbidden}")
    if list(card.glob("attempt.*")):
        fail("unexpected attempt directory on card")
    for name in frameo.rglob("._*"):
        fail(f"AppleDouble file on card: {name.name}")
    for rel in SD_FILES:
        card_path, source_path = card / rel, source_sd / rel
        if card_path.is_symlink() or not card_path.is_file():
            fail(f"card file missing or symlinked: {rel}")
        data = card_path.read_bytes()
        if data != source_path.read_bytes():
            fail(f"card bytes differ from source: {rel}")
        info = manifest["files"].get("sd/" + rel)
        if not info or len(data) != info["bytes"] or hashlib.sha256(data).hexdigest() != info["sha256"]:
            fail(f"card file differs from manifest: {rel}")
    if (card / "Frameo_utilities/frameo_utilities.config").read_bytes() != CONFIG_BODY:
        fail("unexpected config body on card")
    try:
        key = (card / "adbkey").read_text(encoding="utf-8")
    except UnicodeError:
        fail("adbkey on card is not UTF-8")
    if not re.fullmatch(r"[^\s]+ frameo-jailbreak\n", key):
        fail("adbkey on card must be one public key with the frameo-jailbreak comment")
    validate_adb_blob(key.split()[0])
    verify_payload_apk(card / "Frameo_utilities" / PAYLOAD_NAME, manifest,
                       build_tools=build_tools, sdk=sdk, aapt2=aapt2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out", nargs="?", type=Path, default=Path(__file__).resolve().parent / "out-final")
    parser.add_argument("--build-tools", type=Path, help="current build-tools directory containing aapt2 and apksigner")
    parser.add_argument("--android-sdk", type=Path, help="current Android SDK (recorded manifest paths are informational)")
    args = parser.parse_args(argv)
    try:
        manifest = verify_package(args.out, build_tools=args.build_tools, sdk=args.android_sdk)
    except (VerificationError, OSError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"PASS: {args.out.absolute()}")
    print(f"  APK: {PACKAGE} versionCode={manifest['payload']['version_code']} sha256={manifest['payload']['apk_sha256']}")
    print(f"  zip: {args.out.absolute() / 'frameo-jailbreak-sd.zip'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
