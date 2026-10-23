# Frameo 159K — unauthenticated SD auto-run leading to root command injection

## Summary

Frameo `net.frameo.frame` v1.30.19 (versionCode 69880) on the 159K/RK3326/Android 8.1 frame exposes a manufacturer SD-card auto-run path that reaches a privileged shell command builder. A filename containing a single quote breaks out of the quoted shell argument in `SystemCommandsHelper.n()`, allowing arbitrary commands to run as **root** before the APK install even begins.

The result is a local privilege-escalation chain from a removable SD card to root command execution and persistent ADB access.

## Affected components

- `net.frameo.frame` v1.30.19 (69880)
- `SystemCommandsHelper.n(File)` — command injection
- `TaskInstallApkFromSd` — reaches the vulnerable helper
- `InstallHelper.d(File)` — package/version-only validation
- `ConfigurationDelegate` / `AManufacturerUtilities` — unauthenticated SD auto-run trigger
- Frameo 159K (RK3326, Android 8.1); other versions using the same code are likely affected

## Root cause 1 — shell quote injection in `SystemCommandsHelper.n()`

`SystemCommandsHelper` constructs shell commands from a file path:

```java
String str  = "chmod 777 " + u(file.getPath());
...
String str3 = "pm install -r " + u(file.getPath());
```

The quoting helper only wraps the path in single quotes:

```java
return "'" + str + "'";
```

It does **not** escape single quotes inside the path. A filename containing `'` therefore terminates the quoted argument and injects shell syntax.

For example:

```text
x';cd${IFS}$EXTERNAL_STORAGE;sh${IFS}p;#.apk
```

The resulting command is effectively:

```sh
chmod 777 '/storage/.../Frameo_utilities/x'; cd /sdcard; sh p; #.apk'
```

The `#` comments out the trailing `.apk'`. The APK install command is never relevant: the `chmod` command executes first, so the injected command runs even when `pm install` later fails.

No literal `/` is needed in the filename, which keeps it valid on FAT/exFAT.

### Final-path variant

The tested package used a removable-card locator instead of the primary `/sdcard`:

```text
x';sh${IFS}$(find${IFS}${ANDROID_DATA%data}storage${IFS}-maxdepth${IFS}2${IFS}-name${IFS}p_frameo_jb);#.apk
```

`${ANDROID_DATA%data}` expands to `/`, and `${IFS}` supplies spaces. This produces:

```sh
sh /storage/<volume>/p_frameo_jb
```

with the script at the root of the removable card.

## Root cause 2 — unauthenticated SD auto-run

`ConfigurationDelegate.f()` scans storage volumes for:

```text
Frameo_utilities/frameo_utilities.config
```

`ConfigurationDelegate.sdCardMounted()` starts `AManufacturerUtilities` when the config is present. `AWaitForDeferredInitCompleted` also starts the same path at boot.

`AManufacturerUtilities.onResume()` reads `auto_run` from the file without authentication and without a `dev_tools_enabled` gate:

```java
if (Boolean.parseBoolean(propertiesC3.getProperty("auto_push_license"))) {
    arrayList.add("auto_push_license");
} else if (propertiesC3.containsKey("auto_run")) {
    arrayList.addAll(Arrays.asList(
        propertiesC3.getProperty("auto_run").split(",")));
}
```

The useful value is:

```properties
auto_run=action_update_version
```

That selects `install_apk_from_sd`, which reaches `TaskInstallApkFromSd`.

## Exploit chain

1. **Prepare a removable FAT/exFAT SD card**
   - `Frameo_utilities/frameo_utilities.config` with `auto_run=action_update_version`
   - Exactly one `.apk` in `Frameo_utilities`
   - A script such as `p_frameo_jb` at the card root
   - Optional ADB public key for persistence

2. **APK requirements**
   - Package: `net.frameo.frame`
   - `versionCode` greater than `69880` (tested: `69881`)
   - Any signature; `InstallHelper.d()` checks package name and versionCode only, not the signer

3. **Trigger**
   - Insert the card while Frameo is running, or boot with it inserted and let the startup scan run
   - `sdCardMounted` → `AManufacturerUtilities` → `auto_run=action_update_version` → `TaskInstallApkFromSd`

4. **Reach the vulnerable command builder**
   - `TaskInstallApkFromSd` lists `.apk` files in `Frameo_utilities`
   - With one APK and a newer versionCode, it calls `SystemCommandsHelper.n(file)`

5. **Inject root commands through the filename**
   - The injected filename breaks the `chmod 777 '<path>'` quoting
   - The injected `sh ...` command runs as root before `pm install`
   - The APK install failing signature verification does not stop the injection

6. **Persist access**
   - The script can append an ADB public key, set `service.adb.tcp.port` and `persist.adb.tcp.port` to `5555`, and restart adbd
   - ADB over TCP then reaches the frame as root via `su 0 id`

## Preconditions and constraints

- Config must be on **removable** storage; Frameo ignores the primary `/sdcard` for this config
- The attacker needs physical SD-card insertion or a boot with the card present
- `Frameo_utilities` must contain exactly one `.apk`
- macOS AppleDouble files such as `._payload.apk` also end in `.apk` and can trigger `Multiple APK files found`; remove all `._*` files
- The APK install itself can fail; only the preceding `chmod` injection matters
- `sdCardMounted` is the reliable trigger on this firmware; reboot scans can miss the config

## Impact

An attacker with brief physical access to the frame can:

- execute arbitrary commands as root
- append an attacker-controlled ADB key
- enable ADB over TCP persistently
- retain root access after the SD card is removed
- modify system/app data, install software, or extract data

This is a full local privilege escalation from removable media to persistent root.

## Verification

The chain was verified on a 159K: a physically inserted SD card reached `TaskInstallApkFromSd`, the injected filename executed a root script, `result.txt` showed `uid=0(root)`, both ADB port properties were set to `5555`, and ADB over TCP reached `su 0 id` as root.