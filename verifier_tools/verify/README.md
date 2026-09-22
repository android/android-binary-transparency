# Verifier of Binary Transparency for Pixel Factory Images

This repository contains code to read the transparency log for four logs:
  * [Pixel Factory Images Binary Transparency](https://developers.google.com/android/binary_transparency/pixel_overview).
  * [Google System APK Transparency](https://developers.google.com/android/binary_transparency/google1p/overview)
  * [Google Product Application Transparency](https://developers.google.com/android/binary_transparency/google_apk/overview)
  * [Android Mainline Modules Transparency](https://developers.google.com/android/binary_transparency/mainline_modules/log_details)

See the particular section for this tool:
  * [Pixel](https://developers.google.com/android/binary_transparency/pixel_verification#verifying-image-inclusion-inclusion-proof)
  * [Google System APKs](https://developers.google.com/android/binary_transparency/google1p/verification_details#verifying_package_inclusion_inclusion_proof)
  * [Google Product Application](https://developers.google.com/android/binary_transparency/google_apk/verification_details)
  * [Android Mainline Modules](https://developers.google.com/android/binary_transparency/mainline_modules/log_details)

## Files and Directories
* `cmd/verifier/`
  * Contains the binary to read any of the transparency logs. It is embedded with the public keys of the logs to verify log identity.
* `internal/`
  * Internal libraries for the verifier binary.

## Build
This module requires Go 1.25+. Install [here](https://go.dev/doc/install), and run `go build cmd/verifier/verifier.go`.

An executable named `verifier` should be produced upon successful build.

## Usage
The verifier uses the associated checkpoint (depending on the target log) and the log contents to check that your candidate binary is included in the transparency log, i.e. that it is published by Google. The tile directory for each supported log is listed below:
  * Pixel Transparency Log
    * `https://developers.google.com/android/binary_transparency/tile/`
  * Google System APK Transparency Log
    * `https://developers.google.com/android/binary_transparency/google1p/tile/` (old log)
    * `https://www.gstatic.com/android/binary_transparency/google1p/jwt/2026/01/tile/` (latest sharded log)
  * Google Product Application Transparency Log
    * `https://www.gstatic.com/android/binary_transparency/google1p/apk/2026/01/tile/` (old log)
    * `https://www.gstatic.com/android/binary_transparency/google1p/apk/2026/02/tile/` (latest Tessera-backed sharded log)
      * `https://www.gstatic.com/android/binary_transparency/google1p/apk/2026/02/tile/entries/` (for data leaves)
  * Android Mainline Modules Transparency Log
    * `https://www.gstatic.com/android/binary_transparency/mainline/2026/01/tile/` (old log)
    * `https://www.gstatic.com/android/binary_transparency/mainline/2026/02/tile/` (latest Tessera-backed sharded log)
      * `https://www.gstatic.com/android/binary_transparency/mainline/2026/02/tile/entries/` (for data leaves)

### Verification Mode

To verify that a candidate binary is included in a log:
```
$ ./verifier --payload_path=${PAYLOAD_PATH} --log_type=<log_type> [--cache_dir=<path>]
```
where `log_type` is one of the following:
  * `pixel` (for Pixel Factory Images)
  * `google_1p_code` (for Google System APKs)
  * `google_1p_apk` (for Google Product Applications)
  * `mainline_module` (for Android Mainline Modules)

### Pre-fetching & Offline Cache Mode

To pre-fetch and locally cache all entry tiles or legacy info files up to the current checkpoint (without requiring a payload or running an inclusion proof):
```
$ ./verifier --log_type=<log_type> --fetch_entries [--concurrency=16] [--cache_dir=<path>]
```

This enables:
  * **Fast, zero-network verifications:** Subsequent verification runs read directly from local cache without multiple HTTP round trips.
  * **Concurrent tile fetching:** Tessera entry tiles are fetched concurrently using bounded worker threads (configurable via `--concurrency`, defaulting to 16). Full tiles ($W=256$) are immutable and skipped on subsequent runs, making updates fast and incremental.
  * **Custom cache storage:** Pass `--cache_dir` (or `--cache-dir`) to specify a custom directory for the cache. Ideal for persistent CI/CD volumes, container pre-baking, or air-gapped/offline verification bundles.

### Flags

| Flag | Description | Default |
| --- | --- | --- |
| `--log_type`, `--log-type` | Target transparency log (`pixel`, `google_1p_code`, `google_1p_apk`, `mainline_module`). Required. | `""` |
| `--payload_path`, `--payload-path` | Path to the payload file describing the candidate binary. Required for verification mode. | `""` |
| `--fetch_entries`, `--fetch-entries` | Pre-fetch and cache all log entries locally up to the latest checkpoint. | `false` |
| `--concurrency` | Number of concurrent workers for fetching Tessera entry tiles. | `16` |
| `--cache_dir`, `--cache-dir` | Custom root directory for local cache. If unspecified, defaults to system cache. | OS user cache dir |

### Input
The verifier takes a `payload_path` and a `log_type` as input.

#### Pixel
Each Pixel Factory image corresponds to a [payload](https://developers.google.com/android/binary_transparency/pixel_overview#log_content) stored in the transparency log, the format of which is:
```
<build_fingerprint>\n<vbmeta_digest>\n
```
See [here](https://developers.google.com/android/binary_transparency/pixel_verification#construct-the-payload-for-verification) for a few methods detailing how to extract this payload from an image.

#### Google System APK
Each Google System APK corresponds to a [payload](https://developers.google.com/android/binary_transparency/google1p/overview#log_content) stored in the transparency log, the format of which is:
```
<hash>\n<hash_description>\n<package_name>\n<package_version_code>\n
```

Currently, `hash_description` is fixed as `SHA256(Signed Code Transparency JWT)`.
See [here](https://developers.google.com/android/binary_transparency/google1p/verification_details#construct_a_payload_for_verification) to find out how to construct this payload from a candidate APK.

#### Google Product Application
Each Google Product Application corresponds to a [payload](https://developers.google.com/android/binary_transparency/google_apk/overview#log_content) stored in the transparency log, the format of which is:
```
<hash>\n<hash_description>\n<package_name>\n<package_version_code>\n
```

The `hash_description` for Google Product Applications could either be `SHA256(APK)` or `SHA256(APEX)` depending on the file type.
See [here](https://developers.google.com/android/binary_transparency/google_apk/verification_details#construct_a_payload_for_verification) to find out how to construct this payload from a candidate APK.

#### Android Mainline Module
Each Android Mainline Module corresponds to a [payload](https://developers.google.com/android/binary_transparency/mainline_modules/overview#log_content) stored in the transparency log, the format of which is:
```
<hash>\n<hash_description>\n<package_name>\n<package_version_code>\n
```

See [here](https://developers.google.com/android/binary_transparency/google_apk/verification_details#construct_a_payload_for_verification) to find out how to construct this payload from a candidate module APK/APEX.

### Output
The output of the command is written to stdout:
  * `OK. inclusion check success!` if the candidate binary is included in the log.
  * `FAILURE` otherwise.