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

- `test_hubble_parser.py`: Tests HubbleParser version compatibility checking,
  parsing `preinstalled_packages.txt`, 6-state package classification
  (`FACTORY_PREINSTALLED_APK`, `FACTORY_PREINSTALLED_APEX`,
  `UPDATED_SYSTEM_APP`, `UPDATED_MAINLINE_MODULE`, `USER_INSTALLED`,
  `UNKNOWN`), signing certificate lineage vs. co-signing classification
  (`SINGLE_SIGNER`, `KEY_ROTATION_LINEAGE`, `MULTIPLE_SIGNERS`), and package
  query/filtering methods.
- `test_inclusion_proof_check.py`: Tests pre-fetching transparency log entries
  (`--cache_prefetch_concurrency`, `--cache_prefetch_timeout`, `--cache_dir`),
  opt-out (`--no_prefetch`), fail-open fallback on pre-fetch errors/timeouts,
  input validation, exit codes (`0` when output is written vs. `1` on
  execution/input error), split inclusion verification, and support for
  `preinstalled_packages.txt`.
- `test_automate_observation.py`: Tests multi-device pre-fetch retry and latch
  behavior across connected devices, and pre-installed package extraction and
  verification flags.

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

> [!IMPORTANT]
> **Backwards Compatibility Notice:** Uraniborg scripts and `HubbleParser`
> require Hubble output **schema `2.x` (`>= 2.1.0`)**. Major version bumps
> intentionally break compatibility; output files produced by Hubble `1.0.0`
> (or any version `< 2.1.0`) and higher major versions (`>= 3.0.0`) are **not
> supported**.
>
> Minor versions within `2.x` are **additive** and are read on a best-effort
> basis, so previously collected corpora stay readable. For example `2.2.0`
> adds the `signingInfo` object; when reading `2.1.0` output the signing-mode
> helpers report `UNKNOWN` instead of rejecting the observation.

<!-- TODO: Remove legacy risk-scoring documentation (docs/Uraniborg's Preloaded App Risks Scoring Metrics (2020-08) v1.0.pdf) and remaining legacy result categorization helpers in hubble_parser.py / automate_observation.py. -->

## Disclaimer
This is not an officially supported Google product.
