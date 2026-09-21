# Hubble Results
After successful invocation of Hubble app, 8 text files should be produced. For
convenience, the content of the text file are essetentially JSON. Therefore, you
can also use your favorite JSON parsing or viewing tools to navigate the results.

All result files have the following format. It has a version that allows the
reader to identify which version of Hubble that produced the result (in case of
changes in the future). It then has a total field describing the number of
elements of the type of result. This should help detect very basic transmission
errors that leads to truncation of file, for example.

> [!IMPORTANT]
> **Version Compatibility (Schema `2.x`, `>= 2.1.0` Required):** Uraniborg's
> parser (`hubble_parser.py`) and automation tools require Hubble result files
> matching **schema `2.x` (`>= 2.1.0`)** (which include
> `preinstalled_packages.txt`, `isUpdatedSystemApp`, and `isApex`). Major
> version bumps break compatibility; output from Hubble `1.0.0` (or any version
> `< 2.1.0`) and higher major versions (`>= 3.0.0`) is **not supported**.
>
> Minor versions within `2.x` are **additive** and never raise the supported
> floor, so previously collected corpora remain readable and comparable over
> time. Schema `2.2.0` adds the structured `signingInfo` object (lineage vs.
> co-signer metadata) while leaving `certIds` unchanged; when reading `2.1.0`
> output, signing-mode helpers report `UNKNOWN` rather than rejecting the
> observation.

<!-- TODO: Remove legacy categorization / baseline helpers in scripts/python/hubble_parser.py and legacy scoring metrics PDF in docs/. -->

## Components
### Binaries (binaries.txt)
This file enumerates the executable binaries accessible to an untrusted app on
the system. The information included for each binary is:

- hash: This is the SHA256 digest of the binary.
- installPath: The directory the binary is located at.
- name: The filename of the binary.

### Build Information (build.txt)
This file provides a basic enumeration of the build information of the target
device. The information included is:

- apiLevel: The API level of this build (This usually also corresponds to the
OS level).
- bootloaderVersion: The bootloader version of the device at the time the
observation is made. Note that sometimes this may not be available on certain
devices.
- fingerprint: The build fingerprint string that the device identifies as.
- kernelVersion: The kernel version that this device currently runs. Note that
this sometimes include richer informations like the architecture and the build
timestamp of the kernel.
- locale: The locale that this device is set up as. This field is collected to
try to differentiate the case that with everything else constant, there may be
other changes to the device due to the locale variation alone.
- radioVersion: The baseband version. Note that sometimes this may not be
available on certain devices.
- securityPatchLevel: The security patch level as claimed by the OEM.

### Signing Certificates (certificates.txt)
This file enumerates all the certificates that are used to sign the packages
that were found to be installed at the time of observation. The listed fields
are:

- hash: The SHA256 digest of the certificate file.
- encodedCert: The base64 encoded string representation of the individual X509
certificate in DER format. You can decode this string and use your favorite tool
to parse and further analyze the certificates. For instance, after decoding back
to bytes and writing it to a file:<br/>
`openssl x509 -inform der -in <path_to_cert>`

### Device Properties
These are some of the properties that are specific to the device/SKU. This is
essentially information that is obtainable via `adb shell getprop`

- encodedDevProps: The base64 encoded string of the result from executing `adb
shell getprop`.

### Hardware Information
This file includes information about the hardware properties itself. Fields
include:

- boardName: The board name of the device
- brand: The brand of the device
- deviceName: The OEM-given name of the device
- hardwareName: The OEM-given hardware name of the device
- hash: The SHA256 digest of the other properties sorted by alphabetical order
- modelName: The OEM-given model name of the device
- oem: The manufacturer of the device
- productName: The OEM-given product name of the device

### System Libraries (libraries.txt)
This file enumerates all the libraries that are visible to Hubble. The properties
we capture include:

- bits: Whether the library is a 32 or 64 bit library.
- hash: The SHA256 digest of the library.
- installPath: The location where the library is installed at.
- name: The filename of the library.

### Installed Packages (packages.txt)
This file enumerates all installed packages on the system at the time of
observation.

- activities: A list of `activity`s that the package contains (can be empty).
- certIds: SHA256 digest(s) of certificate(s) associated with this package (for
  co-signed packages, the active co-signers; for single-signer packages, the
  signing certificate lineage or single signer). Use `signingInfo` below to
  disambiguate active signers from key rotation lineage.
- description: The description of the application (if available).
- firstInstallTime: The recorded time (in ms) of the first install time of this
package.
- hasCode: A boolean [flag](https://developer.android.com/reference/android/content/pm/ApplicationInfo.html#FLAG_HAS_CODE)
indicating app developer's declaration of whether this package contains code or
is purely data/resource APK.
- hash: The SHA256 digest of the package/APK.
- installLocation: The location where the APK is installed on the system.
- isPreinstalled: A boolean flag indicating whether the APK is preinstalled
(either as the original factory system image package or as an updated version of
a system application) or installed post setup.
- isUpdatedSystemApp: A boolean [flag](https://developer.android.com/reference/android/content/pm/ApplicationInfo.html#FLAG_UPDATED_SYSTEM_APP)
indicating whether this package was installed as an update to a built-in system
application.
- isApex: A boolean flag indicating if this package is an [APEX](https://source.android.com/devices/tech/ota/apex) or not.
- isEnabled: A boolean [flag](https://developer.android.com/reference/android/content/pm/ApplicationInfo.html#enabled)
telling whether at the time of observation, this package is "active" or in the
"disabled" or not running state.
- isFactoryTest: A boolean flag indicating whether the APK is one used for
factory test purposes or not.
- isHidden: A boolean flag indicating whether the APK is visible to the user
from the UI or not at the time the observation is done.
- isSuspended: A boolean [flag](https://developer.android.com/reference/android/content/pm/ApplicationInfo.html#FLAG_SUSPENDED) indicating whether or not the APK is suspended or not at the time of observation.
- isTestOnly: A boolean [flag](https://developer.android.com/reference/android/content/pm/ApplicationInfo.html#FLAG_TEST_ONLY) indicating whether or not the APK is intended for
test only.
- kernelGids: the [kernel group IDs](https://developer.android.com/reference/android/content/pm/PackageInfo.html#gids)
of this package.
- label: the [application label](https://developer.android.com/reference/android/content/pm/PackageManager#getApplicationLabel(android.content.pm.ApplicationInfo)) of this package. This is the field known to
the user as the APK's name.
- name: the package name of this APK (usually in reverse domain format).
- permissionsDeclared: a list of **custom** permissions declared by the app.
- permissionsGranted: a list of permissions that is currently granted to the
package. If observation is done after a factory reset, this represents the state
of pre-granted permissions to this package by the OEM.
- permissionsNotGranted: a list of permissions that is **not** granted to the
package at the time of observation.
- providers: a list of `provider`s in the package.
- receivers: a list of `receiver`s in the package.
- services: a list of `service`s in the package.
- sharedUserId: a string representing the [shared user ID](https://developer.android.com/reference/android/content/pm/PackageInfo.html#sharedUserId) of this package.
- sharedUserLabel: an integer representing the [shared user ID label](https://developer.android.com/reference/android/content/pm/PackageInfo.html#sharedUserLabel) of this
package.
- signingInfo: *(added in schema `2.2.0`; absent in `2.1.0` output)* A nested JSON object capturing structured [`SigningInfo`](https://developer.android.com/reference/android/content/pm/SigningInfo) metadata so that APK Signature Scheme v3 key rotation lineages are cleanly distinguished from multi-signer (co-signed) APKs:
  - `hasMultipleSigners`: A boolean indicating whether the package is simultaneously co-signed by multiple active signers (`SigningInfo.hasMultipleSigners()`). On API < 28 this is derived from the length of the deprecated `PackageInfo.signatures` array, counted *before* digest computation so that a failed digest cannot silently demote a co-signed APK.
  - `hasPastSigningCertificates`: A boolean indicating whether the package has rotated its signing key and includes past ancestor signing certificates in its v3 lineage (`SigningInfo.hasPastSigningCertificates()`). **Tri-state:** on API < 28 the platform exposes no v3 lineage API at all, so this is `null` rather than `false` — rotation is *unobservable* there, not known to be absent. Consumers must not read `null` as "never rotated"; `HubbleParser.classify_package_signing()` reports `UNKNOWN` for it.
  - `apkContentsSigners`: A list of SHA256 certificate digests for the **currently active** signer(s) (`SigningInfo.getApkContentsSigners()`). For single-signer packages (with or without key rotation), this contains exactly 1 element (the current active signer). For co-signed packages (`hasMultipleSigners == true`), this contains all active co-signers.
  - `signingCertificateLineage`: A list of SHA256 certificate digests representing the ordered signing certificate lineage (`SigningInfo.getSigningCertificateHistory()`) from the **oldest (original) ancestor signing certificate at index `0`** to the **current active signing certificate at index `-1`**. When `hasMultipleSigners == true`, this is an empty array `[]` (as Android does not support v3 key rotation for multi-signer APKs). It is also `[]` on API < 28, where no lineage is observable — Hubble deliberately does not fabricate one from the active signers.
  - `platformSignatureMatch`: The verdict from [`PackageManager.checkSignatures(pkgName, "android")`](https://developer.android.com/reference/android/content/pm/PackageManager#checkSignatures(java.lang.String,%20java.lang.String)) — one of `MATCH`, `NO_MATCH`, `NEITHER_SIGNED`, `FIRST_NOT_SIGNED`, `SECOND_NOT_SIGNED`, `UNKNOWN_PACKAGE`, or `UNKNOWN`. Recorded verbatim as an **observation of what `PackageManager` reports to apps**. Per AOSP `ComputerEngine.checkSignaturesInternal()`, it (1) compares the two packages' **current** signer sets for exact set equality, then (2) on failure, if either side has a lineage, retries using only the **oldest** ancestor of each — an explicit backwards-compatibility path for callers predating key rotation. It does **not** consult `CertCapabilities`. See the caution below for why this is *not* used to determine platform signing. `UNKNOWN_PACKAGE` is expected for entries (e.g. `com.android.privatespace`) that `PackageManager` does not resolve as a signature-comparable package.
- splitNames: any names of installed [split APKs](https://developer.android.com/reference/android/content/pm/PackageInfo#splitNames)
of this package.
- usesCleartextTraffic: a boolean [flag](https://developer.android.com/reference/android/content/pm/ApplicationInfo.html#FLAG_USES_CLEARTEXT_TRAFFIC)indicating whether or not this
package would use cleartext network traffic.
- versionCode: An integer indicating this package's version code.
- versionName: A string representing this package's version.

For each of the components, there are further details that are collected:
#### Activity
- name: the name of the activity.
- isEnabled: whether this activity is turned on or not.
- isExported: whether this activity is exported (able to be called externally)
or not.
- labels: the labels (user readable names) of the activity.
- desc: the descriptions of the activity.
- permission: the permission that protects this activity.

#### Provider
- name: the name of the provider.
- isEnabled: whether this provider can be instantiated by the system.
- isExported: whether this provider is available for other apps to use.
- labels: the labels (user readable names) of this provider.
- desc: the description of the provider.
- authority: an URI authority that identifies data offered by the content
provider.
- grantUriPermissions: whether or not those who ordinarily would not have
permission to access the content provider's data can be granted permission to do
so.
- permissionRead: The permission that clients must have to query the content
provider.
- permissionWrite: The permission that clients must have to modify the data
controlled by the content provider.

#### Receiver
- name: the name of the receiver.
- isEnabled: whether this receiver is turned on or not.
- isExported: whether this receiver is exported (can be called externally) or
not.
- labels: the labels (user readable names) of this receiver.
- desc: the descriptions of this receiver.
- permission: the permission that protects this receiver.

#### Service
- name: the name of the service.
- isEnabled: whether this service is turned on or not.
- isExported: whether this service is exported (can be called externally) or
not.
- labels: the labels (user readable names) of this service.
- desc: the descriptions of this service.
- permission: the permission that protects this service.

### Pre-installed Packages (preinstalled_packages.txt)
This file enumerates packages where `isPreinstalled == true`.

> [!NOTE]
> Despite what the filename may suggest, `preinstalled_packages.txt` includes
> **both** factory pre-installed packages and updated system applications
> (`isUpdatedSystemApp == true`). Refer to
> [Determining Package Installation Status](#determining-package-installation-status)
> below for guidance on differentiating between the two states.

## Interpretation
If you launched Hubble on a brand new device (out of the box) or one that has
just gone through factory data reset (FDR), you will be able to observe the
state of the device that is configured by the OEM.

If you launched Hubble on your current device without going through FDR, you
are essentially creating a snapshot of your device based on the installed
packages (including those that are installed post device setup).

### Determining Package Installation Status
By examining `isPreinstalled`, `isUpdatedSystemApp`, and `isApex`, installed
packages can be classified into distinct states; APEX entries require additional
inspection of `installLocation` as described below:

| State | `isPreinstalled` | `isUpdatedSystemApp` | `isApex` | Active Package Location (`installLocation`) | Observed Artifacts & Hash |
| :--- | :---: | :---: | :---: | :--- | :--- |
| **Factory Pre-installed (APK)** | `true` | `false` | `false` | System partitions (`/system/...`, `/vendor/...`, `/product/...`) | Original OEM / ROM image binary |
| **Factory Pre-installed (APEX)** | `true` | `false` | `true` | System partitions, or `/data/apex/active/*@*.decompressed.apex` (decompressed CAPEX) | Original OEM / ROM APEX binary |
| **Updated System Application (APK)** | `true` | `true` | `false` | Data partition (`/data/app/...`) | Updated APK (shadows original OEM binary) |
| **Updated Mainline Module (APEX)** | `true` | `false`* | `true` | Data partition (`/data/apex/active/*@*.apex` ending in `.apex`) | Updated APEX (shadows original OEM binary) |
| **User-Installed Application** | `false` | `false` | `false` | Data partition (`/data/app/...`) | Third-party app installed post-setup |
| **Unknown (`UNKNOWN`)** | any (`false` or `true`) | any | `true` | Unrecognized APEX path (or `isPreinstalled == false`) | Unrecognized OEM / partition layout; surfaces for manual inspection |

> [!IMPORTANT]
> **Measurement Caveat for Updated System Applications (APKs):**
> When `isUpdatedSystemApp == true`, `installLocation`, `hash`, and
> `fileSizeInBytes` describe the updated APK in `/data/app`, **not** the factory
> binary. The original OEM binary is not observable through the Android package
> manager in this state, so these entries will not match factory image hashes.
> Perform an FDR before running Hubble if you need factory binary measurements.

> [!WARNING]
> **Caveat for APEX / Mainline Modules (`isApex == true`):**
> `FLAG_UPDATED_SYSTEM_APP` is a PackageManager concept specific to APKs.
> APEX packages updated via Google Play / Mainline land in `/data/apex/active/...`
> and do **not** set this flag, so `isUpdatedSystemApp` remains `false` (marked `false`*
> in the table above). Therefore, **`isApex == true` entries are not covered by
> `isUpdatedSystemApp`**.
>
> Furthermore, disambiguation **must key on the filename suffix, not just the directory**.
> Per AOSP's `apexd` flow, factory compressed APEX modules (`.capex`, standard on Pixel
> since Android 12) pre-installed under `/system/apex/` are decompressed at boot into
> `/data/apex/decompressed/<name>@<ver>.decompressed.apex` and hard-linked into
> `/data/apex/active/` specifically so the rest of the boot path can treat them uniformly.
> As a consequence, a pristine, never-updated factory Mainline module can present an
> `installLocation` under `/data/apex/active/...` or `/data/apex/decompressed/...`.
> Keying on directory alone would falsely classify pristine factory modules as updated.
> The `.decompressed.apex` suffix is preserved through the hard link.
>
> Inspect `installLocation` using the following disambiguation rules:
>
> | `installLocation` | Meaning |
> | :--- | :--- |
> | `/system/apex/...`, `/vendor/apex/...`, `/system_ext/apex/...`, `/product/apex/...` | **Factory Pre-installed** (uncompressed APEX) |
> | `/data/apex/active/*@*.decompressed.apex`, `/data/apex/decompressed/*@*.decompressed.apex` | **Factory Pre-installed** (compressed CAPEX decompressed at boot, not an update) |
> | `/data/apex/active/*@*.apex` (ending in `.apex`, **not** `.decompressed.apex`) | **Updated Mainline Module** (post-setup OTA update via Play / Mainline; hash reflects updated binary) |
> | Any other path (or `isPreinstalled == false`) | **Unknown (`UNKNOWN`)** (unrecognized OEM APEX layout; emits a warning instead of assuming updated) |

### Determining Package Signing Certificate Lineage vs. Co-Signing
In Android (API 28+ / APK Signature Scheme v3), an APK with multiple associated
certificates in `certIds` can represent two completely different cryptographic
configurations:

1. **Key Rotation Lineage (`KEY_ROTATION_LINEAGE`):** The package has a single
   active signer, but has rotated its signing key from one or more historical
   ancestor certificates (`signingInfo.hasMultipleSigners == false`,
   `signingInfo.hasPastSigningCertificates == true`).
2. **Co-Signed by Multiple Active Signers (`MULTIPLE_SIGNERS`):** The package
   is simultaneously co-signed by two or more active certificates
   (`signingInfo.hasMultipleSigners == true`,
   `signingInfo.hasPastSigningCertificates == false`). Android does not support
   v3 key rotation for multi-signer APKs.

Use the nested `signingInfo` object (or `HubbleParser.classify_package_signing()`,
`get_active_signers()`, `get_signing_lineage()`, and
`get_past_signing_certificates()`) to distinguish these cases:

| Signing Mode (`HubbleParser`) | `signingInfo.hasMultipleSigners` | `signingInfo.hasPastSigningCertificates` | `signingInfo.apkContentsSigners` | `signingInfo.signingCertificateLineage` | Meaning |
| :--- | :---: | :---: | :--- | :--- | :--- |
| **`SINGLE_SIGNER`** | `false` | `false` | `[cert_current]` (len `1`) | `[cert_current]` (len `1`) | Signed by a single certificate with no key rotation history |
| **`KEY_ROTATION_LINEAGE`** | `false` | `true` | `[cert_current]` (len `1`) | `[cert_oldest, ..., cert_current]` (len `>= 2`) | Single active signer (`cert_current`) with ordered v3 key rotation history from `cert_oldest` |
| **`MULTIPLE_SIGNERS`** | `true` | `false` or `null` | `[cert_1, cert_2, ...]` (len `>= 2`) | `[]` (empty) | Simultaneously co-signed by all listed certificates in `apkContentsSigners`. Reported affirmatively even on API < 28, where the signer count is observable. |
| **`UNKNOWN`** (legacy schema) | — | — | — | — | No `signingInfo` object at all (legacy schema `2.1.0` output), or malformed metadata. The flat `certIds` list cannot distinguish a lineage from co-signers, so the mode is never guessed. Use `HubbleParser.has_structured_signing_info()` to detect this. |
| **`UNKNOWN`** (API < 28) | `false` | `null` | `[cert_current]` (len `1`) | `[]` (empty) | Collected on a pre-P device, where PackageManager exposes no v3 lineage API. The package may or may not have rotated its key; Hubble reports `null` instead of asserting `SINGLE_SIGNER`. |

> [!IMPORTANT]
> **Lineage Ordering (`certIds[0]` vs. `apkContentsSigners[0]`):**
> When `signingInfo.hasPastSigningCertificates == true`, Android's
> `getSigningCertificateHistory()` orders certificates from the **oldest
> (retired) ancestor at index `0`** to the **current active signer at the last
> index (`[-1]`)**. Always read `signingInfo.apkContentsSigners` (or call
> `HubbleParser.get_active_signers(pkg)`) to obtain the currently active
> signing certificate(s) rather than indexing `certIds[0]`.

> [!CAUTION]
> **Platform-Package Matching is Directional.**
> Platform-package and shared-UID matching in `HubbleParser`
> (`get_platform_packages()`, `print_platform_packages()`, and
> `get_shared_uid_packages()`) all funnel through
> `HubbleParser.is_platform_signed(pkg)`, which compares the package's
> **active** signer(s) against the platform's **full** lineage
> (`get_platform_signatures()`).
>
> **Never intersect two full certificate sets.** A package that has rotated
> *away* from the platform key still carries that key in its own lineage, so a
> symmetric intersection would keep treating it as platform-signed forever. Only
> the platform side may use the full lineage (as the trust anchor); the candidate
> side must use active signers only.
>
> **`platformSignatureMatch` is deliberately NOT used for this decision.**
> `PackageManager.checkSignatures()` is a legacy, pre-rotation-compatible API,
> not a capability-aware trust check. It compares current signer sets for exact
> equality, then retries with only the oldest ancestor of each lineage, and never
> calls `SigningDetails.checkCapability()`. That makes it unsound in both
> directions here:
>
> | Scenario | `checkSignatures` | `is_platform_signed()` | Why they differ |
> | :--- | :---: | :---: | :--- |
> | Package rotated **away** from the platform key | `MATCH` | `false` | Oldest-ancestor retry compares the *retired* platform cert |
> | Package co-signed by platform key **+** another key | `NO_MATCH` | `true` | Exact set equality fails, but the platform key is an active signer |
>
> Use `HubbleParser.get_platform_signature_match(pkg)` when you specifically want
> the `PackageManager` verdict (e.g. to reason about legacy callers of that API).

> [!WARNING]
> **Signing-lineage capability flags are not observable at all.**
> When a key is rotated, each ancestor node carries
> `SigningDetails.CertCapabilities` flags (`PERMISSION`, `SHARED_USER_ID`,
> `INSTALLED_DATA`, `ROLLBACK`, `AUTH`) which the rotation may **revoke**. The
> framework honours these in its shared-UID join logic and permission subsystem,
> but they are not reachable from any public API — not via `SigningInfo`, and not
> via `checkSignatures()`. Hubble therefore cannot record them.
>
> Consequently a retired platform certificate whose capabilities were revoked is
> indistinguishable from one that retains them, and `is_platform_signed()` may
> **over-approximate** platform trust for un-rotated system packages still signed
> with a retired platform certificate.
