Private Frameo jailbreak SD package
==================================
Built: {{BUILD_DATE}}
Target: {{PACKAGE}} {{VERSION_NAME}}; metadata APK versionCode {{PAYLOAD_VERSION_CODE}}
Payload filename: {{PAYLOAD_NAME}}
Public-key comment: {{ADB_KEY_COMMENT}}

This package uses the existing manufacturer auto-run/filename injection on the
159K/RK3326/Android 8.1 target. Frameo must already obtain noninteractive root
through su. Only a public ADB key is included; keep its matching private key
on the host. The metadata APK does not replace the installed Frameo app.

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
saves current keys, metadata, properties and service state per attempt, then
merges the supplied exact key blob into CURRENT keys. It does not rebuild active
keys from an old recovery snapshot. All essential changes are checked.
Current/recovery/merged files must contain at least one validated key. Empty,
blank-only and malformed-vendor-only files are rejected before active changes.
The supplied key file must contain exactly one valid key on one line.

A done marker means local keys, properties and adbd service state were verified.
It does not prove host authentication or persistence after reboot. Preserve
result.txt and the per-attempt snapshots even after a failure. The manufacturer
activity has its own vendor-key/restart side effect before this script starts.

Recovery
--------
1. If the framework fails or the screen is black, REMOVE THE CARD FIRST. Keep
   physical access and the original authorized host key. Do not erase/reflash.
2. Read result.txt and the attempt's recorded rollback status. A failed change
   attempts to restore that attempt's exact original keys and properties.
3. Keep adb_keys.before (the separate immutable cleaned recovery copy) and all
   per-attempt snapshots. Never restore an empty, partial or unvalidated file.
   Do not overwrite newer active keys blindly with an older recovery snapshot.
4. Use the owner's existing recovery path to restore matching exact key bytes,
   owner/mode/SELinux context and original properties if automatic rollback did
   not finish. An original property may be empty; keep that empty argument
   inside a device-side script.
5. Restart adbd with one detached device-side helper and a status record. Never
   issue a bare stop or nested su/sh restart string: a lost adbd argument can
   stop the entire Android framework. Restore properties BEFORE restarting.
6. Diagnose the failure before explicitly rearming. Keep snapshots, remove the
   one-shot guard only for that deliberate retry, and publish the config LAST.

The tested root syntax is su 0 <command>. ADB shell access is distinct from root:
./connect.sh <frame-ip> requires the target host, checks the connection and then
su 0 id. Supplying ADB_PRIVATE_KEY uses a dedicated owned host server and leaves
unrelated ADB servers alone.

Files
-----
Frameo_utilities/  exactly one metadata APK and auto-run config before first run
p_frameo_jb        root payload
adbkey             Android ADB public key
adb_keys.before    separate cleaned original recovery snapshot (after execution)
started / done    first-attempt guard / successful local-completion marker
result.txt         payload result, including failure/rollback diagnostics
attempt snapshots exact per-attempt keys, metadata, properties and service state
