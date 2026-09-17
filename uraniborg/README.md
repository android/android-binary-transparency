# Uraniborg

Uraniborg is a public observatory/repository that collects and hosts information
about preinstalled apps. Users can use tools in this repository to get a
"snapshot" on the state of installed devices. When used on a new device prior to
or skipping accounts set-up, the state of preinstalled packages on the device
can be obtained.

This repository currently contains code that can be used to build an explorer
app (APK) called Hubble.

The name of this project and its components are mainly inspired by the field of
astronomy.

- [Uraniborg](https://en.wikipedia.org/wiki/Uraniborg) is a Danish
astronomical observatory.
- [Hubble](https://en.wikipedia.org/wiki/Hubble_Space_Telescope) is a space telescope used for astronomy observations.

## Documentation

Below are links to more specific documentations.

### Data Extraction
- [How to build Hubble](docs/hubble_setup.md)
- [How to use Hubble](docs/deploying_hubble.md)
- [How to automate data extraction](docs/automate_observation.md)

### Data Interpretation
- [Interpreting Hubble results](docs/hubble_results.md)

## Testing

Unit tests for the Python automation and verification scripts are located in
`scripts/python/tests/` and use the `pytest` framework:

- `test_inclusion_proof_check.py`: Tests pre-fetching transparency log entries
  (`--cache_prefetch_concurrency`, `--cache_prefetch_timeout`, `--cache_dir`),
  opt-out (`--no_prefetch`), fail-open fallback on pre-fetch errors/timeouts,
  input validation, exit codes (`0` when output is written vs. `1` on
  execution/input error), and split inclusion verification.
- `test_automate_observation.py`: Tests multi-device pre-fetch retry and latch
  behavior across connected devices.

To set up a virtual environment and run the test suite from the repository root:

```bash
# Set up a virtual environment and install pytest (one-time setup)
python3 -m venv .venv
source .venv/bin/activate
pip install pytest

# Run the test suite
pytest uraniborg/scripts/python/tests/
```

## Version
The current version info can be found within the VERSION file, and in the
build.gradle file of the Hubble app.

## Disclaimer
This is not an officially supported Google product.
