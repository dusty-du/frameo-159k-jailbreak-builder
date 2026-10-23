Private Frameo jailbreak SD package
==================================
Built: {{BUILD_DATE}}
Target: {{PACKAGE}} {{VERSION_NAME}}; metadata APK versionCode {{PAYLOAD_VERSION_CODE}}
Payload filename: {{PAYLOAD_NAME}}
Public-key comment: {{ADB_KEY_COMMENT}}

This package is intended for a first-time clean deployment. No prior ADB or root
access is required by the package flow: the vulnerable manufacturer helper is
expected to execute the injected command as root on the tested firmware. Only a
public ADB key is included; keep its matching private key on the host. Generate
the key pair locally; no device connection is needed to build the package. The
metadata APK does not replace the installed Frameo app.

A clean device may have no /data/misc/adb/adb_keys file or an empty one. The
payload accepts either as an empty baseline, creates the file with the supplied
public key, and preserves nonempty existing keys.

The repaired tooling has host-only validation. It has not been deployed to a
frame. Factory-stock applicability and cold-boot TCP ADB persistence are not
established by the historical evidence.

Future manual insertion
-----------------------
Copy the contents of sd/ to the ROOT of a FAT/exFAT removable card. Keep exactly
one .apk in Frameo_utilities. Remove every AppleDouble ._* file, including
._*.apk. Primary /sdcard is ignored for the config. Insert while Frameo is
running. Boot scans may miss the card; do not force-stop the home app.

One-shot completion
-------------------
The guard is established before result.txt is opened and the trigger config is
removed before changing device state. Failed attempts stay disarmed. The script
records an absent/empty/present baseline, metadata, properties and service state
per attempt, then merges the supplied exact key blob into CURRENT keys. It does
not rebuild active keys from an old recovery snapshot. All essential changes are
checked. A genuinely absent or zero-byte current key file is accepted as the
clean baseline. A nonempty current/recovery file must contain at least one
validated key. Blank-only, malformed, partial or inconsistent files are
rejected. The supplied key file must contain exactly one valid key on one line.

For a clean baseline, adb_keys.before.state records absent or empty;
adb_keys.before contains key bytes only when a nonempty prior key set existed.

A done marker means local keys, properties and adbd service state were verified.
It does not prove host authentication or persistence after reboot. Preserve
result.txt and the per-attempt snapshots even after a failure. The manufacturer
activity has its own vendor-key/restart side effect before this script starts.

Recovery
--------
1. If the framework fails or the screen is black, REMOVE THE CARD FIRST. Keep
   physical access. If the device had a nonempty prior key set, keep its matching
   private key; a clean baseline has no prior key. Do not erase/reflash.
2. Read result.txt and the attempt's recorded rollback status. A failed change
   attempts to restore that attempt's exact original baseline and properties.
3. Keep adb_keys.before.state and all per-attempt snapshots. adb_keys.before
   contains key bytes only for a nonempty prior key set. Never treat an empty or
   partial file as a valid nonempty backup. Do not overwrite newer active keys
   blindly with an older recovery snapshot.
4. If a nonempty prior key set existed, restore matching exact key bytes,
   owner/mode/SELinux context and original properties. If the baseline was
   absent, remove the generated key file; if it was empty, restore the recorded
   empty file and metadata. An original property may be empty; keep that empty
   argument inside a device-side script.
5. Restart adbd with one detached device-side helper and a status record. Never
   issue a bare stop or nested su/sh restart string: a lost adbd argument can
   stop the entire Android framework. Restore properties BEFORE restarting.
6. Diagnose the failure before explicitly rearming. Keep snapshots, remove the
   one-shot guard only for that deliberate retry, and publish the config LAST.

The tested root syntax is su 0 <command>. ADB access is created by this payload;
a clean run has no prior ADB channel. Run ./connect.sh <frame-ip> from the host
only after result.txt contains done, with ADB_PRIVATE_KEY pointing at the private
key matching adbkey. It checks the connection and then su 0 id; it uses a
dedicated owned host server and leaves unrelated ADB servers alone.

Files
-----
Frameo_utilities/  exactly one metadata APK and auto-run config before first run
p_frameo_jb        root payload
adbkey             Android ADB public key
adb_keys.before    original key bytes only for a nonempty prior key set
adb_keys.before.state  absent | empty | present baseline record
started / done    first-attempt guard / successful local-completion marker
result.txt         payload result, including failure/rollback diagnostics
attempt snapshots exact per-attempt keys, metadata, properties and service state
