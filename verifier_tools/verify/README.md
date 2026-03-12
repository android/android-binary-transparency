# Verifier of Binary Transparency for Pixel Factory Images

This repository contains code to read the transparency log for two logs:
  * [Pixel Factory Images Binary Transparency](https://developers.google.com/android/binary_transparency/pixel_overview).
  * [Google System APK Transparency](https://developers.google.com/android/binary_transparency/google1p/overview)

See the particular section for this tool:
  * [Pixel](https://developers.google.com/android/binary_transparency/pixel_verification#verifying-image-inclusion-inclusion-proof)
  * [Google System APKs](https://developers.google.com/android/binary_transparency/google1p/verification_details#verifying_package_inclusion_inclusion_proof)

## Files and Directories
* `cmd/verifier/`
  * Contains the binary to read any of the transparency logs. It is embedded with the public keys of the logs to verify log identity.
* `internal/`
  * Internal libraries for the verifier binary.

## Build
This module requires Go 1.17. Install [here](https://go.dev/doc/install), and run `go build cmd/verifier/verifier.go`.

An executable named `verifier` should be produced upon successful build.

## Usage
The verifier uses the associated checkpoint (depending on the target log) and the log contents to check that your candidate binary is included in the transparency log, i.e. that it is published by Google. The tile directory for each supported log is listed below:
  * Pixel Transparency Log
    * `https://developers.google.com/android/binary_transparency/tile/`
  * Google System APK Transparency Log
    * `https://developers.google.com/android/binary_transparency/google1p/tile/`

To run the verifier after you have built it in the previous section:
```
$ ./verifier --payload_path=${PAYLOAD_PATH} --log_type=<log_type>
```
where `log_type` is either `pixel` or `google_system_apk`.

### Input
The verifier takes a `payload_path` and a `log_type `as input.

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

### Output
The output of the command is written to stdout:
  * `OK. inclusion check success!` if the candidate binary is included in the log. Depending on which log, this means either the [Pixel claim](https://developers.google.com/android/binary_transparency/pixel_overview#claimant_model) or the [Google System APK claim](https://developers.google.com/android/binary_transparency/google1p/overview#claimant_model) is true,
  * `FAILURE` otherwise.