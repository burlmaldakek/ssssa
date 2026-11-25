# FairPlayed Lab — on-device prototype

This is an experimental, no-JIT iOS build based on the supplied FairPlayed source.
It keeps the original native Objective-C/C implementation and adds a UI for:

- importing an IPA from Files and running the existing direct-import decrypt attempt;
- testing whether a licensed app already installed from the App Store is accessible through the LaunchServices path used by the upstream research;
- exporting successful output files and the device log through the Share Sheet.

## Important limitation

This is a **feasibility prototype, not a confirmed arbitrary-IPA decryptor**.

The upstream project explicitly reports that `fairplayd` can read the helper's installed app bundle but cannot read app data containers. An IPA imported after the helper has been installed lives in the helper's data container, so the direct-import path is expected to fail on stock iOS. The upstream flow works around this by embedding the target `.app` in the helper bundle *before* the helper is signed and installed. An installed iOS app cannot modify its own signed bundle at runtime.

The installed-app probe tests a different possible route. Enter an exact bundle ID to call the explicit LaunchServices resolver. On iOS 27, broad enumeration may be denied to unentitled apps. Leave it empty to test all user apps. Only apps licensed to the Apple Account signed in on the device are expected to be eligible. Success is not guaranteed; the result depends on the iOS version, sandbox access, and FairPlay behavior.

## JIT and device requirements

- No JIT is used. The decryptor is native Objective-C/C and calls the kernel syscall directly, as in the supplied source.
- No jailbreak or TrollStore dependency was added.
- The original mechanism uses `mremap_encrypted` (syscall 489) and is confirmed by the upstream author only on stock iOS 27.0.1.
- The app's minimum deployment target remains iOS 16.0, but that does **not** mean the mechanism is verified on every iOS 16+ release.
- The iPhone should be signed in to the Apple Account that owns the app license.

## Build without owning a Mac

The included GitHub Actions workflow builds an **unsigned IPA** on a GitHub-hosted macOS runner:

1. Push this folder's contents to a GitHub repository.
2. Open **Actions → Build FairPlayed Lab (unsigned IPA)**.
3. Run the workflow with **Run workflow**.
4. Download the `FairPlayed-Lab-unsigned-IPA` artifact.
5. Sign and install that IPA with your normal sideloading/signing method.

The build artifact is unsigned. GitHub Actions performs compilation, not developer-account signing. The installed app still needs a valid signature and provisioning profile from the signing method you use.

## On-device use

1. Install FairPlayed Lab.
2. Open **Import IPA and test** to select an IPA in Files. The app copies it into its own Documents directory, extracts it, inspects Mach-O slices, and attempts the original FairPlay operation.
3. If the direct import attempt fails, the app also runs the upstream SC_Info/path variants and logs the result.
4. Use **Test installed apps** to probe a licensed app already installed on the phone. Enter an exact bundle ID to narrow the scan; broad enumeration may be denied on stock iOS 27.
5. Use **Share logs / decrypted IPAs** to send `fairplayed.log` and any successful IPA outputs.

## What remains unsolved

The original macOS scripts perform host-only operations:

- `embed_ipa.sh` prepares the target bundle before signing;
- `fpdecrypt.sh` invokes Xcode, signs the new helper, installs it through `devicectl`, then pulls output back;
- `verify_ipa.sh` uses macOS `otool` to verify the final IPA.

The iOS app ports the archive parsing, Mach-O processing, verification heuristics and ZIP creation to native code, but it cannot reproduce the host-side embed/sign/install cycle inside a normal sandboxed app. The main research target is therefore whether the installed-app route provides a usable path for licensed apps without changing the device's security state.

## Source layout

- `FairPlayed/FairPlayed/main.m` — on-device UI and execution flow
- `FairPlayed/FairPlayed/fpcore.c` — Mach-O parsing and FairPlay syscall logic
- `FairPlayed/FairPlayed/zipio.c` — IPA ZIP reader/writer
- `.github/workflows/build-unsigned.yml` — cloud macOS build workflow
