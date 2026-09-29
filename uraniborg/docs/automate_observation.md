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

`python3 automate_observation.py`

Upon successful execution, you should see messages like:
```
INFO:automate_observation.py:main(560): SUCCESS! Hubble was successfully deployed and executed on connected device ABCDEF012345.
INFO:automate_observation.py:main(561): Hubble output files can be found at: some/valid/path
```

If you see the final SUCCESS message, feel free to ignore earlier ERROR messages.
Those resulted from some files that cannot be extracted from device, but does not
affect the core files required for further analysis.

### Selecting Devices

By default, the script observes **every** device listed by `adb devices`, one
after another. To observe only specific devices, pass their serial numbers with
`-s`/`--serial`. The flag may be repeated, and devices are processed in the
order given:

```bash
python3 automate_observation.py --serial ABCDEF012345 --serial 9876543210FEDCBA
```

A requested serial that is not connected is not silently skipped: it is logged
as an error, reported as `FAILED` in the final summary, and makes the script
exit with code `1`. The remaining requested devices are still observed.

### Machine-Readable Progress (`--events`)

Log messages are meant for people and may change between versions. Wrappers
such as CI jobs or device-lab scripts should use `--events` instead: it writes
a stream of progress events as [JSON Lines](https://jsonlines.org/), one JSON
object per line, flushed as each event happens.

```bash
# Write events to a file (overwritten if it exists):
python3 automate_observation.py --events run.jsonl

# Or stream them on stdout:
python3 automate_observation.py --events - | my-wrapper
```

With `--events -`, stdout carries **only** events. Everything else that would
otherwise have gone to stdout is sent to stderr, including output from child
processes such as the verifier and the Xiaomi manual-install prompt. Logging
always goes to stderr. Without `--events`, nothing changes: log output, exit
codes and the results layout are the same. If the `--events` destination
cannot be opened, the script exits with code `1` before doing anything else.
If writing events fails partway through (for example, the reading process
exits), a warning is logged and the run continues without events.

#### Event schema (version 1)

Every event has these fields:

| Field | Meaning |
| :--- | :--- |
| `v` | Schema version, currently `1` |
| `ts` | UTC timestamp, ISO 8601 with milliseconds, e.g. `2026-01-02T03:04:05.678Z` |
| `type` | One of the event types below |

Optional fields are left out rather than set to `null`.

| `type` | Fields | When |
| :--- | :--- | :--- |
| `run_started` | `argv` (arguments, without the script name), `pid` | First event of every run |
| `step` | `step`, `state` (`started` / `finished` / `failed`), `device`\*, `duration_ms`\*\*, `message`\* | Around each phase (see below) |
| `devices` | `devices` (list of `{serial, unauthorized, model?, product?, device?}`), `selected` (serials to observe), `missing` (requested via `--serial` but not connected) | Once, after listing devices |
| `device_started` | `device` | Before processing each selected device |
| `device_finished` | `device`, `status`, `results_dir`\*, `error`\* | After each selected device, and once for each missing serial |
| `run_finished` | `exit_code`, `ok`, `summary`, `error`\* | Last event of a run that ends normally, exits early, raises, or is stopped by Ctrl-C or `SIGTERM` (see [End of stream](#end-of-stream)) |

\* only when relevant. \*\* only on `finished` / `failed`.

Both `error` fields are `{reason, message}`: `reason` is a stable code (see
[Error reasons](#error-reasons)) to match on, and `message` is human-readable
text that may change. Step `message` is free text.

**Steps.** Run-level steps have no `device` field and run in this order:
`build_hubble` (only without `-H`), `verify_hubble`, `check_adb`,
`start_adb_server`, `list_devices`. Per-device steps carry `device`:
`uninstall_previous` (only if Hubble was already installed), `install_hubble`,
`launch_hubble`, `wait_for_results`, `extract_results`, `extract_selinux`, and,
with `--perform_inclusion_proof_check`, `inclusion_proof_prefetch` (only when
pre-fetching is attempted) and `inclusion_proof_check`. A failed
`inclusion_proof_prefetch` is not fatal: verification falls back to fetching
entries on demand.

**Device status.** `device_finished.status` and `summary[serial].status` use the
same four outcomes as the final log summary:

| `status` | Meaning |
| :--- | :--- |
| `success` | Results collected, and the inclusion proof check (if requested) completed |
| `partial_check_incomplete` | Results collected, but the inclusion proof check could not complete (for example, the package list was missing or unreadable, or the output could not be written) |
| `partial_error` | Results collected, but an unexpected error occurred afterwards, or the run was stopped (`error.reason` is `interrupted` or `terminated`) |
| `failed` | No results collected (including unauthorized and not-connected devices, and devices stopped before results were collected) |

> [!IMPORTANT]
> `success` does **not** mean every APK was found in the transparency log. A
> completed check records a per-split `inclusion_proof_verified` result, which
> may be `false`, in `packages_with_inclusion_proof_signal.txt` (or
> `preinstalled_packages_with_inclusion_proof_signal.txt`) inside
> `results_dir`. Read that file to decide whether the APKs are in the log.

`results_dir` is present whenever results were collected, including both
`partial_*` outcomes.

**Run outcome.** `run_finished.summary` maps each serial, in the order it was
requested (or discovered, without `--serial`), to `{status, results_dir?}`.
If the run is stopped early (`interrupted`, `terminated` or
`unexpected_error`), `summary` lists only the devices that reached
`device_finished`; devices that had not been processed yet are absent.
`ok` is `true` only when `exit_code` is `0` **and** there is no `error`. Treat
`ok`, not `exit_code`, as the success signal: when the script stops before
processing any device (for example, no device is connected), it still exits
with code `0`, but `run_finished.error` explains why.

#### Error reasons

`run_finished.error.reason`:

| `reason` | Meaning |
| :--- | :--- |
| `unsupported_platform` | The host OS is not supported |
| `android_sdk_not_found` | Rebuilding Hubble (no `-H`) failed: Android SDK not found |
| `hubble_build_failed` | Rebuilding Hubble failed (Gradle or symlink error) |
| `invalid_hubble_apk` | The `-H` path is not an `.apk` |
| `adb_not_found` | `adb` is not installed |
| `adb_server_failed` | The adb server could not be started |
| `adb_devices_failed` | `adb devices` failed (without `--serial`) |
| `no_devices` | No device is connected (without `--serial`) |
| `unexpected_error` | An unhandled exception; `exit_code` is `1` |
| `interrupted` | Interrupted with Ctrl-C; `exit_code` is `130` |
| `terminated` | Stopped by `SIGTERM`; `exit_code` is `143` |

`device_finished.error.reason`:

| `reason` | Meaning | `status` |
| :--- | :--- | :--- |
| `not_connected` | Requested via `--serial` but not connected | `failed` |
| `unauthorized` | ADB is not authorized on the device | `failed` |
| `uninstall_failed` | A previous Hubble installation could not be removed | `failed` |
| `install_failed` | Hubble could not be installed | `failed` |
| `launch_failed` | Hubble could not be launched | `failed` |
| `no_results` | Hubble produced no results in time | `failed` |
| `extract_failed` | Results could not be pulled from the device | `failed` |
| `inclusion_proof_check_incomplete` | The inclusion proof check could not complete | `partial_check_incomplete` |
| `unexpected_error` | An unhandled exception while processing the device | `failed` or `partial_error` |
| `interrupted` | Ctrl-C while processing the device | `failed` or `partial_error` |
| `terminated` | `SIGTERM` while processing the device | `failed` or `partial_error` |

For the last three, `status` is `partial_error` if results had already been
collected, otherwise `failed`.

Example, for one device with inclusion proofs:

```json
{"v": 1, "ts": "2026-01-02T03:04:05.678Z", "type": "run_started", "argv": ["--events", "-", "--perform_inclusion_proof_check", "--verifier_path=/path/to/verifier"], "pid": 4242}
{"v": 1, "ts": "2026-01-02T03:04:05.690Z", "type": "step", "step": "verify_hubble", "state": "started"}
{"v": 1, "ts": "2026-01-02T03:04:05.691Z", "type": "step", "step": "verify_hubble", "state": "finished", "duration_ms": 1}
...
{"v": 1, "ts": "2026-01-02T03:04:06.100Z", "type": "devices", "devices": [{"serial": "ABCDEF012345", "unauthorized": false, "model": "Pixel_9"}], "selected": ["ABCDEF012345"], "missing": []}
{"v": 1, "ts": "2026-01-02T03:04:06.101Z", "type": "device_started", "device": "ABCDEF012345"}
{"v": 1, "ts": "2026-01-02T03:04:06.102Z", "type": "step", "step": "install_hubble", "state": "started", "device": "ABCDEF012345"}
...
{"v": 1, "ts": "2026-01-02T03:09:41.310Z", "type": "device_finished", "device": "ABCDEF012345", "status": "success", "results_dir": "/path/to/results/google/.../000"}
{"v": 1, "ts": "2026-01-02T03:09:41.312Z", "type": "run_finished", "exit_code": 0, "ok": true, "summary": {"ABCDEF012345": {"status": "success", "results_dir": "/path/to/results/google/.../000"}}}
```

#### End of stream

`run_finished` cannot be written if the process is killed with `SIGKILL`, the
Python interpreter crashes, or the host goes down. **A stream that ends without
`run_finished` means the run failed.** Do not infer success from the
`device_finished` events seen so far.

With `--events`, `SIGTERM` (how CI systems usually enforce timeouts and
cancellations) is caught so that `run_finished` can be written. The script then
still terminates by `SIGTERM`, so the parent process sees the same exit status
as before. Without `--events`, `SIGTERM` handling is unchanged.

#### Compatibility

The schema is a stable contract. New event types and new fields may be added
without changing `v`, so consumers should ignore types and fields they do not
recognize. Removing a field or changing what it means requires a new `v`.

## Performing Inclusion Proof Checks

You can automatically verify extracted package APK splits against Android Binary
Transparency logs by passing `--perform_inclusion_proof_check` along with the
path to the `verifier` executable:

```bash
python3 automate_observation.py \
  --perform_inclusion_proof_check \
  --verifier_path=/path/to/verifier
```

The results are written to `packages_with_inclusion_proof_signal.txt` (or
`preinstalled_packages_with_inclusion_proof_signal.txt` when
`--check_preinstalled_only` is specified) inside the device's results
directory. Note that `inclusion_proof_check.py` (when invoked
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
* `--check_preinstalled_only`: Performs inclusion proof checks against
  `preinstalled_packages.txt` instead of `packages.txt`, writing results to
  `preinstalled_packages_with_inclusion_proof_signal.txt`.

### Pulling Pre-installed APKs Only
By default, `--pull-all-apks` downloads all packages listed in `packages.txt`.
You can pass `--pull-preinstalled-apks-only` to download only pre-installed
packages (from `preinstalled_packages.txt`):

```bash
python3 automate_observation.py --pull-preinstalled-apks-only
```

### Running Unit Tests
Unit tests for the inclusion proof check, pre-fetching, and multi-device
workflows are located in `scripts/python/tests/`. You can run them with
`pytest`:

```bash
pytest uraniborg/scripts/python/tests/
```
