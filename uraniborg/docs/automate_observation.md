# How to automate data extraction

## Prerequisites
Please follow the same prerequisites on [deploying hubble](deploying_hubble.md).

Additionally, you need to make sure that you have `Python 3.5` or above installed
on your system.

## Using the script
You will be able to find a number of Python 3 scripts in the `scripts/python`
directory.

In order to automate the data extraction process, which is covered by
[deploying hubble](deploying_hubble.md), you will be able to make use of the
`automate_observation.py` python script. Make sure that your test/target device
is connected via ADB, and issue the following command from your terminal:

`python3 automate_observations.py`

Upon successful execution, you should see messages like:
```
INFO:automate_observation.py:main(560): SUCCESS! Hubble was successfully deployed and executed on connected device ABCDEF012345.
INFO:automate_observation.py:main(561): Hubble output files can be found at: some/valid/path
```

If you see the final SUCCESS message, feel free to ignore earlier ERROR messages.
Those resulted from some files that cannot be extracted from device, but does not
affect the core files required for further analysis.

## Performing Inclusion Proof Checks

You can automatically verify extracted package APK splits against Android Binary
Transparency logs by passing `--perform_inclusion_proof_check` along with the
path to the `verifier` executable:

```bash
python3 automate_observation.py \
  --perform_inclusion_proof_check \
  --verifier_path=/path/to/verifier
```

The results are written to `packages_with_inclusion_proof_signal.txt` inside the
device's results directory. Note that `inclusion_proof_check.py` (when invoked
standalone or in CI) exits with code `0` whenever the check runs and writes the
output JSON—even if individual APK splits fail their inclusion proof
(`"inclusion_proof_verified": false`)—and exits with code `1` only when
execution itself fails (e.g. missing/corrupt `packages.txt` or I/O errors).

### Pre-fetching and Local Caching (Enabled by Default)
When `--perform_inclusion_proof_check` is specified, `automate_observation.py`
**automatically pre-fetches and caches transparency log entries locally** (using
`verifier --fetch_entries`) before verifying individual packages. This avoids
slow sequential HTTP downloads during per-package checks and reuses the local
cache across multiple connected devices.

You can customize caching and pre-fetching behavior with the following optional
flags:
* `--cache_prefetch_concurrency <N>`: Number of concurrent workers used when
  pre-fetching Tessera entry tiles (default: `16`).
* `--cache_prefetch_timeout <SECONDS>`: Timeout in seconds for the pre-fetching
  step (default: `600`). If pre-fetching exceeds this ceiling (e.g. on a cold
  cache over a slow or proxied link), it logs a warning and gracefully falls
  back to on-demand tile fetching during verification. Because cached tile
  writes are atomic, any tiles downloaded before the timeout are preserved in
  the local cache and reused.
* `--cache_dir <PATH>`: Custom root directory for the local cache (defaults to
  the system user cache directory).
* `--no_prefetch`: Disables pre-fetching log entries up front, falling back to
  on-demand fetching during individual package verifications.

### Running Unit Tests
Unit tests for the inclusion proof check, pre-fetching, and multi-device
workflows are located in `scripts/python/tests/`. You can run them with
`pytest`:

```bash
pytest uraniborg/scripts/python/tests/
```
