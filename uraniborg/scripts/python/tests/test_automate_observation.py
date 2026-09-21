#!/usr/bin/python3
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Unit tests for automate_observation.py CLI parsing and multi-device prefetch latch."""

import argparse
import io
import json
import os
from pathlib import Path
import sys
import tarfile
from unittest import mock
import zlib
import pytest

# Ensure uraniborg/scripts/python is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import automate_observation
import inclusion_proof_check


def _make_mock_device(serial: str):
  dev = mock.Mock()
  dev.serial_number = serial
  dev.unauthorized = False
  return dev


def test_parse_arguments_defaults_and_validation(
    monkeypatch: pytest.MonkeyPatch,
):
  """Verifies default flag values and --verifier_path requirement."""
  monkeypatch.setattr(
      sys,
      "argv",
      [
          "automate_observation.py",
          "--perform_inclusion_proof_check",
          "--verifier_path=/path/to/verifier",
      ],
  )
  args = automate_observation.parse_arguments()
  assert args.perform_inclusion_proof_check is True
  assert args.verifier_path == "/path/to/verifier"
  assert args.cache_dir is None
  assert (
      args.cache_prefetch_concurrency
      == inclusion_proof_check.DEFAULT_PREFETCH_CONCURRENCY
  )
  assert (
      args.cache_prefetch_timeout
      == inclusion_proof_check.DEFAULT_PREFETCH_TIMEOUT
  )
  assert args.no_prefetch is False
  assert args.pull_preinstalled_apks_only is False
  assert args.check_preinstalled_only is False

  # Missing --verifier_path when --perform_inclusion_proof_check is set should error
  monkeypatch.setattr(
      sys,
      "argv",
      ["automate_observation.py", "--perform_inclusion_proof_check"],
  )
  with pytest.raises(SystemExit):
    automate_observation.parse_arguments()


@mock.patch("automate_observation.os.path.isfile", return_value=True)
@mock.patch("automate_observation.extract_selinux_policies")
@mock.patch("automate_observation.extract_results_and_apks")
@mock.patch("automate_observation.wait_for_results")
@mock.patch("automate_observation.launch_hubble")
@mock.patch("automate_observation.clear_logcat")
@mock.patch("automate_observation.install_hubble")
@mock.patch("automate_observation.is_xiaomi_phone")
@mock.patch("automate_observation.is_hubble_installed")
@mock.patch("automate_observation.AdbWrapper")
@mock.patch("automate_observation.adb_installed", return_value=True)
@mock.patch("automate_observation.verify_hubble", return_value=True)
@mock.patch("automate_observation.supported_platform", return_value=True)
@mock.patch("inclusion_proof_check.perform_inclusion_proof_check", return_value=True)
@mock.patch("inclusion_proof_check.prefetch_log_entries")
def test_multi_device_prefetch_latch_and_retry(
    mock_prefetch: mock.MagicMock,
    mock_perform_check: mock.MagicMock,
    mock_supported: mock.MagicMock,
    mock_verify_hubble: mock.MagicMock,
    mock_adb_installed: mock.MagicMock,
    mock_adb_wrapper_cls: mock.MagicMock,
    mock_is_installed: mock.MagicMock,
    mock_is_xiaomi: mock.MagicMock,
    mock_install: mock.MagicMock,
    mock_clear_logcat: mock.MagicMock,
    mock_launch: mock.MagicMock,
    mock_wait_results: mock.MagicMock,
    mock_extract_results: mock.MagicMock,
    mock_extract_selinux: mock.MagicMock,
    mock_isfile: mock.MagicMock,
    monkeypatch: pytest.MonkeyPatch,
):
  """Verifies once-across-devices latch: retries on failure, latches on success."""
  monkeypatch.setattr(
      sys,
      "argv",
      [
          "automate_observation.py",
          "-H",
          "/path/to/hubble.apk",
          "-o",
          "/tmp/out",
          "--perform_inclusion_proof_check",
          "--verifier_path=/path/to/verifier",
          "--cache_dir=/custom/cache",
          "--cache_prefetch_concurrency=24",
          "--cache_prefetch_timeout=1200",
      ],
  )

  # 3 connected devices
  mock_adb_wrapper_cls.start_server.return_value = True
  mock_adb_wrapper_cls.devices.return_value = [
      _make_mock_device("DEV1"),
      _make_mock_device("DEV2"),
      _make_mock_device("DEV3"),
  ]

  mock_is_installed.return_value = False
  mock_is_xiaomi.return_value = False
  mock_install.return_value = True
  mock_launch.return_value = True
  mock_wait_results.return_value = "/sdcard/hubble/results"
  mock_extract_results.side_effect = [
      "/tmp/out/DEV1",
      "/tmp/out/DEV2",
      "/tmp/out/DEV3",
  ]

  # DEV1 prefetch fails (returns False) -> DEV2 retries and succeeds (returns True) -> DEV3 skips prefetch
  mock_prefetch.side_effect = [False, True]

  automate_observation.main()

  # prefetch_log_entries called only twice (DEV1 failed, DEV2 succeeded, DEV3 skipped)
  assert mock_prefetch.call_count == 2
  _, kwargs_prefetch = mock_prefetch.call_args_list[0]
  assert kwargs_prefetch["cache_dir"] == "/custom/cache"
  assert kwargs_prefetch["concurrency"] == 24
  assert kwargs_prefetch["timeout"] == 1200

  # perform_inclusion_proof_check called for all 3 devices with prefetch=False
  assert mock_perform_check.call_count == 3
  for call in mock_perform_check.call_args_list:
    assert call.kwargs["prefetch"] is False
    assert call.kwargs["cache_dir"] == "/custom/cache"
    assert call.kwargs["timeout"] == 1200


@mock.patch("automate_observation.extract_selinux_policies")
@mock.patch("automate_observation.extract_results_and_apks")
@mock.patch("automate_observation.wait_for_results")
@mock.patch("automate_observation.launch_hubble")
@mock.patch("automate_observation.clear_logcat")
@mock.patch("automate_observation.install_hubble")
@mock.patch("automate_observation.is_xiaomi_phone")
@mock.patch("automate_observation.is_hubble_installed")
@mock.patch("automate_observation.AdbWrapper")
@mock.patch("automate_observation.adb_installed", return_value=True)
@mock.patch("automate_observation.verify_hubble", return_value=True)
@mock.patch("automate_observation.supported_platform", return_value=True)
@mock.patch("inclusion_proof_check.perform_inclusion_proof_check", return_value=True)
@mock.patch("inclusion_proof_check.prefetch_log_entries", return_value=True)
def test_multi_device_skips_prefetch_when_packages_file_missing(
    mock_prefetch: mock.MagicMock,
    mock_perform_check: mock.MagicMock,
    mock_supported: mock.MagicMock,
    mock_verify_hubble: mock.MagicMock,
    mock_adb_installed: mock.MagicMock,
    mock_adb_wrapper_cls: mock.MagicMock,
    mock_is_installed: mock.MagicMock,
    mock_is_xiaomi: mock.MagicMock,
    mock_install: mock.MagicMock,
    mock_clear_logcat: mock.MagicMock,
    mock_launch: mock.MagicMock,
    mock_wait_results: mock.MagicMock,
    mock_extract_results: mock.MagicMock,
    mock_extract_selinux: mock.MagicMock,
    monkeypatch: pytest.MonkeyPatch,
):
  """Verifies prefetch is not fired on DEV1 if packages.txt is missing, and defaults apply."""
  monkeypatch.setattr(
      sys,
      "argv",
      [
          "automate_observation.py",
          "-H",
          "/path/to/hubble.apk",
          "-o",
          "/tmp/out",
          "--perform_inclusion_proof_check",
          "--verifier_path=/path/to/verifier",
      ],
  )

  mock_adb_wrapper_cls.start_server.return_value = True
  mock_adb_wrapper_cls.devices.return_value = [
      _make_mock_device("DEV1"),
      _make_mock_device("DEV2"),
  ]

  mock_is_installed.return_value = False
  mock_is_xiaomi.return_value = False
  mock_install.return_value = True
  mock_launch.return_value = True
  mock_wait_results.return_value = "/sdcard/hubble/results"
  mock_extract_results.side_effect = ["/tmp/out/DEV1", "/tmp/out/DEV2"]

  # DEV1 packages.txt missing -> False; DEV2 packages.txt exists -> True
  with mock.patch(
      "automate_observation.os.path.isfile", side_effect=[False, True]
  ):
    automate_observation.main()

  # Only called once (on DEV2), and concurrency defaulted to DEFAULT_PREFETCH_CONCURRENCY
  assert mock_prefetch.call_count == 1
  _, kwargs_prefetch = mock_prefetch.call_args_list[0]
  assert (
      kwargs_prefetch["concurrency"]
      == inclusion_proof_check.DEFAULT_PREFETCH_CONCURRENCY
  )
  assert kwargs_prefetch["cache_dir"] is None
  assert mock_perform_check.call_count == 2


@mock.patch("automate_observation.os.path.isfile", return_value=True)
@mock.patch("automate_observation.extract_selinux_policies")
@mock.patch("automate_observation.extract_results_and_apks")
@mock.patch("automate_observation.wait_for_results")
@mock.patch("automate_observation.launch_hubble")
@mock.patch("automate_observation.clear_logcat")
@mock.patch("automate_observation.install_hubble")
@mock.patch("automate_observation.is_xiaomi_phone")
@mock.patch("automate_observation.is_hubble_installed")
@mock.patch("automate_observation.AdbWrapper")
@mock.patch("automate_observation.adb_installed", return_value=True)
@mock.patch("automate_observation.verify_hubble", return_value=True)
@mock.patch("automate_observation.supported_platform", return_value=True)
@mock.patch("inclusion_proof_check.perform_inclusion_proof_check", return_value=True)
@mock.patch("inclusion_proof_check.prefetch_log_entries")
def test_multi_device_no_prefetch_flag_disables_all_prefetches(
    mock_prefetch: mock.MagicMock,
    mock_perform_check: mock.MagicMock,
    mock_supported: mock.MagicMock,
    mock_verify_hubble: mock.MagicMock,
    mock_adb_installed: mock.MagicMock,
    mock_adb_wrapper_cls: mock.MagicMock,
    mock_is_installed: mock.MagicMock,
    mock_is_xiaomi: mock.MagicMock,
    mock_install: mock.MagicMock,
    mock_clear_logcat: mock.MagicMock,
    mock_launch: mock.MagicMock,
    mock_wait_results: mock.MagicMock,
    mock_extract_results: mock.MagicMock,
    mock_extract_selinux: mock.MagicMock,
    mock_isfile: mock.MagicMock,
    monkeypatch: pytest.MonkeyPatch,
):
  """Verifies --no_prefetch flag disables prefetch across all devices."""
  monkeypatch.setattr(
      sys,
      "argv",
      [
          "automate_observation.py",
          "-H",
          "/path/to/hubble.apk",
          "-o",
          "/tmp/out",
          "--perform_inclusion_proof_check",
          "--verifier_path=/path/to/verifier",
          "--no_prefetch",
      ],
  )

  mock_adb_wrapper_cls.start_server.return_value = True
  mock_adb_wrapper_cls.devices.return_value = [
      _make_mock_device("DEV1"),
      _make_mock_device("DEV2"),
  ]

  mock_is_installed.return_value = False
  mock_is_xiaomi.return_value = False
  mock_install.return_value = True
  mock_launch.return_value = True
  mock_wait_results.return_value = "/sdcard/hubble/results"
  mock_extract_results.side_effect = ["/tmp/out/DEV1", "/tmp/out/DEV2"]

  automate_observation.main()

  mock_prefetch.assert_not_called()
  assert mock_perform_check.call_count == 2
  assert mock_perform_check.call_args_list[0].kwargs["prefetch"] is False
  assert mock_perform_check.call_args_list[1].kwargs["prefetch"] is False


def test_parse_arguments_preinstalled_flags(
    monkeypatch: pytest.MonkeyPatch,
):
  """Verifies --pull-preinstalled-apks-only and --check_preinstalled_only."""
  monkeypatch.setattr(
      sys,
      "argv",
      [
          "automate_observation.py",
          "--pull-preinstalled-apks-only",
          "--perform_inclusion_proof_check",
          "--check_preinstalled_only",
          "--verifier_path=/path/to/verifier",
      ],
  )
  args = automate_observation.parse_arguments()
  assert args.pull_preinstalled_apks_only is True
  assert args.check_preinstalled_only is True


def test_extract_apks_from_preinstalled_packages(tmp_path: Path):
  """Verifies extract_apks_from_device uses explicit preinstalled_only intent."""
  preinstall_file = tmp_path / "preinstalled_packages.txt"
  preinstall_file.write_text(json.dumps({
      "version": "2.1.0",
      "totalPreinstalledPackages": 1,
      "preinstalledPackages": [{
          "name": "com.android.settings",
          "installLocation": "/system/priv-app/Settings/Settings.apk",
      }],
  }))

  mock_adb = mock.Mock()
  mock_adb.pull.return_value = True
  logger = mock.Mock()

  apks_out = str(tmp_path / "apks")
  failed = automate_observation.extract_apks_from_device(
      mock_adb,
      str(preinstall_file),
      apks_out,
      logger,
      preinstalled_only=True,
  )
  assert failed == {}
  mock_adb.pull.assert_called_once()

  # Verify an empty "packages": [] does NOT fall through to "preinstalledPackages"
  empty_packages_file = tmp_path / "packages.txt"
  empty_packages_file.write_text(json.dumps({
      "version": "2.1.0",
      "packages": [],
      "preinstalledPackages": [{
          "name": "com.android.settings",
          "installLocation": "/system/priv-app/Settings/Settings.apk",
      }],
  }))
  mock_adb.pull.reset_mock()
  failed_empty = automate_observation.extract_apks_from_device(
      mock_adb,
      str(empty_packages_file),
      apks_out,
      logger,
      preinstalled_only=False,
  )
  assert failed_empty == {}
  mock_adb.pull.assert_not_called()


@mock.patch("automate_observation.os.path.isfile", return_value=True)
@mock.patch("automate_observation.os.path.exists", return_value=True)
@mock.patch("automate_observation.extract_selinux_policies")
@mock.patch("automate_observation.extract_results_and_apks")
@mock.patch("automate_observation.wait_for_results")
@mock.patch("automate_observation.launch_hubble")
@mock.patch("automate_observation.clear_logcat")
@mock.patch("automate_observation.install_hubble")
@mock.patch("automate_observation.is_xiaomi_phone")
@mock.patch("automate_observation.is_hubble_installed")
@mock.patch("automate_observation.AdbWrapper")
@mock.patch("automate_observation.adb_installed", return_value=True)
@mock.patch("automate_observation.verify_hubble", return_value=True)
@mock.patch("automate_observation.supported_platform", return_value=True)
@mock.patch("inclusion_proof_check.perform_inclusion_proof_check", return_value=True)
@mock.patch("inclusion_proof_check.prefetch_log_entries", return_value=True)
def test_main_pull_preinstalled_apks_only_and_check_preinstalled_only(
    mock_prefetch: mock.MagicMock,
    mock_perform_check: mock.MagicMock,
    mock_supported: mock.MagicMock,
    mock_verify_hubble: mock.MagicMock,
    mock_adb_installed: mock.MagicMock,
    mock_adb_wrapper_cls: mock.MagicMock,
    mock_is_installed: mock.MagicMock,
    mock_is_xiaomi: mock.MagicMock,
    mock_install: mock.MagicMock,
    mock_clear_logcat: mock.MagicMock,
    mock_launch: mock.MagicMock,
    mock_wait_results: mock.MagicMock,
    mock_extract_results: mock.MagicMock,
    mock_extract_selinux: mock.MagicMock,
    mock_exists: mock.MagicMock,
    mock_isfile: mock.MagicMock,
    monkeypatch: pytest.MonkeyPatch,
):
  """Verifies --pull-preinstalled-apks-only and --check_preinstalled_only execution paths."""
  monkeypatch.setattr(
      sys,
      "argv",
      [
          "automate_observation.py",
          "-H",
          "/path/to/hubble.apk",
          "-o",
          "/tmp/out",
          "--pull-preinstalled-apks-only",
          "--perform_inclusion_proof_check",
          "--check_preinstalled_only",
          "--verifier_path=/path/to/verifier",
      ],
  )
  mock_adb_wrapper_cls.start_server.return_value = True
  mock_adb_wrapper_cls.devices.return_value = [_make_mock_device("DEV1")]
  mock_is_installed.return_value = False
  mock_is_xiaomi.return_value = False
  mock_install.return_value = True
  mock_launch.return_value = True
  mock_wait_results.return_value = "/sdcard/hubble/results"
  mock_extract_results.return_value = "/tmp/out/DEV1"

  automate_observation.main()

  mock_extract_results.assert_called_once()
  assert mock_extract_results.call_args[0][4] is True  # extract_apks
  assert mock_extract_results.call_args.kwargs["pull_preinstalled_only"] is True

  mock_perform_check.assert_called_once()
  checked_file = mock_perform_check.call_args[0][1]
  assert checked_file.endswith("preinstalled_packages.txt")


@mock.patch("automate_observation.os.path.isfile", return_value=False)
@mock.patch("automate_observation.extract_selinux_policies")
@mock.patch("automate_observation.extract_results_and_apks")
@mock.patch("automate_observation.wait_for_results")
@mock.patch("automate_observation.launch_hubble")
@mock.patch("automate_observation.clear_logcat")
@mock.patch("automate_observation.install_hubble")
@mock.patch("automate_observation.is_xiaomi_phone")
@mock.patch("automate_observation.is_hubble_installed")
@mock.patch("automate_observation.AdbWrapper")
@mock.patch("automate_observation.adb_installed", return_value=True)
@mock.patch("automate_observation.verify_hubble", return_value=True)
@mock.patch("automate_observation.supported_platform", return_value=True)
@mock.patch("inclusion_proof_check.perform_inclusion_proof_check")
@mock.patch("inclusion_proof_check.prefetch_log_entries")
def test_main_check_preinstalled_only_fails_loudly_when_file_missing(
    mock_prefetch: mock.MagicMock,
    mock_perform_check: mock.MagicMock,
    mock_supported: mock.MagicMock,
    mock_verify_hubble: mock.MagicMock,
    mock_adb_installed: mock.MagicMock,
    mock_adb_wrapper_cls: mock.MagicMock,
    mock_is_installed: mock.MagicMock,
    mock_is_xiaomi: mock.MagicMock,
    mock_install: mock.MagicMock,
    mock_clear_logcat: mock.MagicMock,
    mock_launch: mock.MagicMock,
    mock_wait_results: mock.MagicMock,
    mock_extract_results: mock.MagicMock,
    mock_extract_selinux: mock.MagicMock,
    mock_isfile: mock.MagicMock,
    monkeypatch: pytest.MonkeyPatch,
):
  """Verifies --check_preinstalled_only fails loudly instead of falling back to packages.txt."""
  monkeypatch.setattr(
      sys,
      "argv",
      [
          "automate_observation.py",
          "-H",
          "/path/to/hubble.apk",
          "-o",
          "/tmp/out",
          "--perform_inclusion_proof_check",
          "--check_preinstalled_only",
          "--verifier_path=/path/to/verifier",
      ],
  )
  mock_adb_wrapper_cls.start_server.return_value = True
  mock_adb_wrapper_cls.devices.return_value = [_make_mock_device("DEV1")]
  mock_is_installed.return_value = False
  mock_is_xiaomi.return_value = False
  mock_install.return_value = True
  mock_launch.return_value = True
  mock_wait_results.return_value = "/sdcard/hubble/results"
  mock_extract_results.return_value = "/tmp/out/DEV1"

  with pytest.raises(SystemExit) as exc_info:
    automate_observation.main()
  assert exc_info.value.code == 1

  mock_prefetch.assert_not_called()
  mock_perform_check.assert_not_called()


@mock.patch("automate_observation.extract_apks_from_device")
def test_classify_dir_pull_preinstalled_only_fails_loudly_when_file_missing(
    mock_extract_apks: mock.MagicMock, tmp_path: Path
):
  """Verifies classify_dir_using_build_fingerprint fails loudly if preinstalled_packages.txt is absent."""
  build_json_content = json.dumps({
      "version": "2.0.1",
      "buildInfo": [{"fingerprint": "google/lynx/lynx:15/BP1A/123:user/release-keys"}],
  })
  staging_dir = tmp_path / "staging"
  staging_dir.mkdir()

  def fake_pull(src, dst):
    if src.endswith("build.txt"):
      Path(dst).write_text(build_json_content)
      return True
    # Simulate Hubble < 2.1.0 pull: creates results/packages.txt, NOT preinstalled_packages.txt
    res_dir = Path(dst) / "results"
    res_dir.mkdir(parents=True, exist_ok=True)
    (res_dir / "packages.txt").write_text(json.dumps({"packages": []}))
    return True

  mock_adb = mock.Mock()
  mock_adb.pull.side_effect = fake_pull
  logger = mock.Mock()

  result_dir = automate_observation.classify_dir_using_build_fingerprint(
      mock_adb,
      "/sdcard/hubble/results",
      str(tmp_path),
      extract_apks=True,
      logger=logger,
      pull_preinstalled_only=True,
      tmp_dir=str(staging_dir),
  )

  assert result_dir is None
  assert (staging_dir / "device_build.txt").is_file()
  logger.error.assert_called_once()
  mock_extract_apks.assert_not_called()


@mock.patch("automate_observation.os.path.isfile", return_value=True)
@mock.patch("automate_observation.set_up_logging")
@mock.patch("automate_observation.extract_selinux_policies")
@mock.patch("automate_observation.extract_results_and_apks")
@mock.patch("automate_observation.wait_for_results")
@mock.patch("automate_observation.launch_hubble")
@mock.patch("automate_observation.clear_logcat")
@mock.patch("automate_observation.install_hubble")
@mock.patch("automate_observation.is_xiaomi_phone")
@mock.patch("automate_observation.is_hubble_installed")
@mock.patch("automate_observation.AdbWrapper")
@mock.patch("automate_observation.adb_installed", return_value=True)
@mock.patch("automate_observation.verify_hubble", return_value=True)
@mock.patch("automate_observation.supported_platform", return_value=True)
@mock.patch("inclusion_proof_check.perform_inclusion_proof_check")
@mock.patch("inclusion_proof_check.prefetch_log_entries", return_value=True)
def test_main_multi_device_verification_failure_partial_success_and_exit_code(
    mock_prefetch: mock.MagicMock,
    mock_perform_check: mock.MagicMock,
    mock_supported: mock.MagicMock,
    mock_verify_hubble: mock.MagicMock,
    mock_adb_installed: mock.MagicMock,
    mock_adb_wrapper_cls: mock.MagicMock,
    mock_is_installed: mock.MagicMock,
    mock_is_xiaomi: mock.MagicMock,
    mock_install: mock.MagicMock,
    mock_clear_logcat: mock.MagicMock,
    mock_launch: mock.MagicMock,
    mock_wait_results: mock.MagicMock,
    mock_extract_results: mock.MagicMock,
    mock_extract_selinux: mock.MagicMock,
    mock_set_up_logging: mock.MagicMock,
    mock_isfile: mock.MagicMock,
    monkeypatch: pytest.MonkeyPatch,
):
  """Verifies PARTIAL SUCCESS vs SUCCESS logging and sys.exit(1) when verification fails on one device."""
  monkeypatch.setattr(
      sys,
      "argv",
      [
          "automate_observation.py",
          "-H",
          "/path/to/hubble.apk",
          "-o",
          "/tmp/out",
          "--perform_inclusion_proof_check",
          "--verifier_path=/path/to/verifier",
      ],
  )
  mock_logger = mock.Mock()
  mock_set_up_logging.return_value = mock_logger

  mock_adb_wrapper_cls.start_server.return_value = True
  mock_adb_wrapper_cls.devices.return_value = [
      _make_mock_device("DEV1"),
      _make_mock_device("DEV2"),
  ]

  mock_is_installed.return_value = False
  mock_is_xiaomi.return_value = False
  mock_install.return_value = True
  mock_launch.return_value = True
  mock_wait_results.return_value = "/sdcard/hubble/results"
  mock_extract_results.side_effect = ["/tmp/out/DEV1", "/tmp/out/DEV2"]

  # DEV1 fails inclusion proof verification, DEV2 succeeds
  mock_perform_check.side_effect = [False, True]

  with pytest.raises(SystemExit) as exc_info:
    automate_observation.main()
  assert exc_info.value.code == 1

  assert mock_perform_check.call_count == 2
  assert mock_extract_selinux.call_count == 2

  mock_logger.warning.assert_any_call(
      "PARTIAL SUCCESS: Hubble data collection succeeded on connected "
      "device %s, but inclusion proof verification failed (exiting 1).",
      "DEV1",
  )
  mock_logger.info.assert_any_call(
      "SUCCESS! Hubble was successfully deployed and executed on "
      "connected device %s.",
      "DEV2",
  )
  mock_logger.info.assert_any_call(
      "Hubble output files can be found at: %s", "/tmp/out/DEV1"
  )
  mock_logger.info.assert_any_call(
      "Hubble output files can be found at: %s", "/tmp/out/DEV2"
  )


@mock.patch("automate_observation.set_up_logging")
@mock.patch("automate_observation.extract_selinux_policies")
@mock.patch("automate_observation.extract_results_and_apks")
@mock.patch("automate_observation.wait_for_results")
@mock.patch("automate_observation.launch_hubble")
@mock.patch("automate_observation.clear_logcat")
@mock.patch("automate_observation.install_hubble")
@mock.patch("automate_observation.remove_previous_installation")
@mock.patch("automate_observation.is_xiaomi_phone", return_value=False)
@mock.patch("automate_observation.is_hubble_installed")
@mock.patch("automate_observation.AdbWrapper")
@mock.patch("automate_observation.adb_installed", return_value=True)
@mock.patch("automate_observation.verify_hubble", return_value=True)
@mock.patch("automate_observation.supported_platform", return_value=True)
def test_main_multi_device_error_isolation_across_stages(
    mock_supported: mock.MagicMock,
    mock_verify_hubble: mock.MagicMock,
    mock_adb_installed: mock.MagicMock,
    mock_adb_wrapper_cls: mock.MagicMock,
    mock_is_installed: mock.MagicMock,
    mock_is_xiaomi: mock.MagicMock,
    mock_remove_prev: mock.MagicMock,
    mock_install: mock.MagicMock,
    mock_clear_logcat: mock.MagicMock,
    mock_launch: mock.MagicMock,
    mock_wait_results: mock.MagicMock,
    mock_extract_results: mock.MagicMock,
    mock_extract_selinux: mock.MagicMock,
    mock_set_up_logging: mock.MagicMock,
    monkeypatch: pytest.MonkeyPatch,
):
  """Verifies per-device failures in main() isolate cleanly and continue to remaining devices."""
  monkeypatch.setattr(
      sys,
      "argv",
      [
          "automate_observation.py",
          "-H",
          "/path/to/hubble.apk",
          "-o",
          "/tmp/out",
      ],
  )
  mock_logger = mock.Mock()
  mock_set_up_logging.return_value = mock_logger

  dev_unauth = _make_mock_device("DEV_UNAUTH")
  dev_unauth.unauthorized = True
  dev_uninstall_fail = _make_mock_device("DEV_UNINSTALL_FAIL")
  dev_install_fail = _make_mock_device("DEV_INSTALL_FAIL")
  dev_install_rc_fail = _make_mock_device("DEV_INSTALL_RC_FAIL")
  dev_launch_fail = _make_mock_device("DEV_LAUNCH_FAIL")
  dev_wait_fail = _make_mock_device("DEV_WAIT_FAIL")
  dev_extract_fail = _make_mock_device("DEV_EXTRACT_FAIL")
  dev_ok = _make_mock_device("DEV_OK")

  mock_adb_wrapper_cls.start_server.return_value = True
  mock_adb_wrapper_cls.devices.return_value = [
      dev_unauth,
      dev_uninstall_fail,
      dev_install_fail,
      dev_install_rc_fail,
      dev_launch_fail,
      dev_wait_fail,
      dev_extract_fail,
      dev_ok,
  ]

  def make_adb_wrapper(serial: str, _logger):
    wrapper = mock.Mock()
    wrapper.serial_number = serial
    wrapper.error_message = ""
    return wrapper

  mock_adb_wrapper_cls.side_effect = make_adb_wrapper

  # 7 authorized devices reach is_hubble_installed:
  # DEV_UNINSTALL_FAIL (True -> remove fails),
  # DEV_INSTALL_FAIL..DEV_EXTRACT_FAIL (False),
  # DEV_OK (True -> remove succeeds)
  mock_is_installed.side_effect = [
      True,
      False,
      False,
      False,
      False,
      False,
      True,
  ]
  mock_remove_prev.side_effect = [False, True]

  # 6 devices reach install_hubble:
  # - DEV_INSTALL_FAIL fails via output line
  # - DEV_INSTALL_RC_FAIL fails via adb.install return code (verifies per-device adb_wrapper.error_message isolation)
  # - remaining 4 succeed
  def fake_install(adb_wrapper, _args, _logger):
    if adb_wrapper.serial_number == "DEV_INSTALL_FAIL":
      adb_wrapper.error_message = "Failure [INSTALL_FAILED_VERSION_DOWNGRADE]"
      return False
    if adb_wrapper.serial_number == "DEV_INSTALL_RC_FAIL":
      adb_wrapper.error_message = "adb: failed to install: device offline"
      return False
    return True

  mock_install.side_effect = fake_install

  # 4 devices reach launch_hubble: DEV_LAUNCH_FAIL fails (setting adb_wrapper.error_message), remaining 3 succeed
  def fake_launch(adb_wrapper):
    if adb_wrapper.serial_number == "DEV_LAUNCH_FAIL":
      adb_wrapper.error_message = "Error: Activity class does not exist"
      return False
    return True

  mock_launch.side_effect = fake_launch

  # 3 devices reach wait_for_results: DEV_WAIT_FAIL returns None, remaining 2 succeed
  mock_wait_results.side_effect = [None, "/sdcard/res", "/sdcard/res"]

  # 2 devices reach extract_results_and_apks: DEV_EXTRACT_FAIL returns None, DEV_OK succeeds
  mock_extract_results.side_effect = [None, "/tmp/out/DEV_OK"]

  automate_observation.main()

  # Verify exact call counts at each pipeline stage (ensuring all side_effects were consumed)
  assert mock_adb_wrapper_cls.call_count == 7
  assert mock_is_installed.call_count == 7
  assert mock_remove_prev.call_count == 2
  assert mock_install.call_count == 6
  assert mock_clear_logcat.call_count == 4
  assert mock_launch.call_count == 4
  assert mock_wait_results.call_count == 3
  assert mock_extract_results.call_count == 2
  assert "tmp_dir" in mock_extract_results.call_args.kwargs
  assert mock_extract_selinux.call_count == 1
  assert mock_extract_selinux.call_args[0][1] == "/tmp/out/DEV_OK"

  # Verify error logging for each isolated device failure with concrete error messages
  mock_logger.error.assert_any_call(
      "Please authorize device with serial number %s for ADB via device GUI.",
      "DEV_UNAUTH",
  )
  mock_logger.error.assert_any_call(
      "Failed to remove previous Hubble installation."
  )
  mock_logger.error.assert_any_call(
      "Error installing Hubble: %s",
      "Failure [INSTALL_FAILED_VERSION_DOWNGRADE]",
  )
  mock_logger.error.assert_any_call(
      "Error installing Hubble: %s",
      "adb: failed to install: device offline",
  )
  mock_logger.error.assert_any_call(
      "Failed to launch Hubble: %s",
      "Error: Activity class does not exist",
  )
  mock_logger.error.assert_any_call(
      "Failed to obtain results from Hubble execution."
  )
  mock_logger.error.assert_any_call(
      "Failed to extract results from target device (%s).",
      "DEV_EXTRACT_FAIL",
  )

  # Only DEV_OK should reach final SUCCESS logging
  mock_logger.info.assert_any_call(
      "SUCCESS! Hubble was successfully deployed and executed on "
      "connected device %s.",
      "DEV_OK",
  )
  mock_logger.info.assert_any_call(
      "Hubble output files can be found at: %s", "/tmp/out/DEV_OK"
  )


def test_install_hubble_propagates_failure_line_to_error_message(
    tmp_path: Path,
):
  """Verifies install_hubble sets adb_wrapper.error_message on all failure paths without mutating shared args."""
  apk_file = tmp_path / "hubble.apk"
  apk_file.write_text("dummy apk")
  logger = mock.Mock()

  # 1. Output line containing "fail" when adb.install() returns True
  args = argparse.Namespace(hubble=str(apk_file))

  mock_adb_1 = mock.Mock()
  mock_adb_1.error_message = ""
  mock_adb_1.install.return_value = True
  mock_adb_1.get_result.return_value = [
      "Performing Streamed Install",
      "Failure [INSTALL_FAILED_INSUFFICIENT_STORAGE]\n",
  ]

  assert automate_observation.install_hubble(mock_adb_1, args, logger) is False
  assert (
      mock_adb_1.error_message == "Failure [INSTALL_FAILED_INSUFFICIENT_STORAGE]"
  )
  assert not hasattr(args, "error_message")

  # 2. Second device whose adb.install() returns False does NOT inherit device 1's error_message
  mock_adb_2 = mock.Mock()
  mock_adb_2.error_message = ""
  mock_adb_2.install.return_value = False
  assert automate_observation.install_hubble(mock_adb_2, args, logger) is False
  assert mock_adb_2.error_message == "adb install failed"
  assert not hasattr(args, "error_message")

  # 3. Missing APK path and directory APK path populate adb_wrapper.error_message
  args.hubble = str(tmp_path / "nonexistent.apk")
  mock_adb_3 = mock.Mock()
  mock_adb_3.error_message = ""
  assert automate_observation.install_hubble(mock_adb_3, args, logger) is False
  assert "does not exist!" in mock_adb_3.error_message

  args.hubble = str(tmp_path)
  mock_adb_4 = mock.Mock()
  mock_adb_4.error_message = ""
  assert automate_observation.install_hubble(mock_adb_4, args, logger) is False
  assert "is not a file" in mock_adb_4.error_message


def test_extract_apks_from_device_retry_via_tmp_and_failure_cleanup(
    tmp_path: Path,
):
  """Verifies direct pull, /data/local/tmp retry fallback, rm cleanup, and rmdir on failure."""
  packages_file = tmp_path / "packages.txt"
  packages_file.write_text(
      json.dumps({
          "version": "2.1.0",
          "packages": [
              {
                  "name": "com.app.direct_ok",
                  "installLocation": "/data/app/direct_ok/base.apk",
              },
              {
                  "name": "com.app.retry_ok",
                  "installLocation": "/data/app/retry_ok/retry_ok.apk",
              },
              {
                  "name": "com.app.cp_fail",
                  "installLocation": "/data/app/cp_fail/cp_fail.apk",
              },
              {
                  "name": "com.app.retry_pull_fail",
                  "installLocation": "/data/app/retry_pull_fail/pull_fail.apk",
              },
          ],
      })
  )

  mock_adb = mock.Mock()

  def fake_pull(src: str, dst: str) -> bool:
    if src == "/data/app/direct_ok/base.apk":
      return True
    if src == "/data/local/tmp/retry_ok.apk":
      return True
    return False

  def fake_shell(cmd: list[str]) -> bool:
    if cmd == ["cp", "/data/app/cp_fail/cp_fail.apk", "/data/local/tmp"]:
      return False
    return True

  mock_adb.pull.side_effect = fake_pull
  mock_adb.shell.side_effect = fake_shell
  logger = mock.Mock()

  apks_dir = tmp_path / "apks"
  failed = automate_observation.extract_apks_from_device(
      mock_adb,
      str(packages_file),
      str(apks_dir),
      logger,
      preinstalled_only=False,
  )

  assert failed == {
      "com.app.cp_fail": "/data/app/cp_fail/cp_fail.apk",
      "com.app.retry_pull_fail": "/data/app/retry_pull_fail/pull_fail.apk",
  }

  # Successful packages keep their target directories; failed ones are cleaned up via os.rmdir
  assert (apks_dir / "com.app.direct_ok").is_dir()
  assert (apks_dir / "com.app.retry_ok").is_dir()
  assert not (apks_dir / "com.app.cp_fail").exists()
  assert not (apks_dir / "com.app.retry_pull_fail").exists()

  # Verify cp and rm shell invocations for the retried packages
  mock_adb.shell.assert_any_call(
      ["cp", "/data/app/retry_ok/retry_ok.apk", "/data/local/tmp"]
  )
  mock_adb.shell.assert_any_call(["rm", "/data/local/tmp/retry_ok.apk"])
  mock_adb.shell.assert_any_call(
      ["cp", "/data/app/cp_fail/cp_fail.apk", "/data/local/tmp"]
  )
  mock_adb.shell.assert_any_call(
      ["cp", "/data/app/retry_pull_fail/pull_fail.apk", "/data/local/tmp"]
  )


def test_extract_apks_from_device_input_validation_edge_cases(tmp_path: Path):
  """Verifies extract_apks_from_device handles invalid arguments, corrupt JSON, and malformed package entries."""
  mock_adb = mock.Mock()
  mock_adb.pull.return_value = True
  logger = mock.Mock()
  apks_dir = str(tmp_path / "apks")

  # 1. Empty apks_dir
  assert (
      automate_observation.extract_apks_from_device(
          mock_adb, str(tmp_path / "packages.txt"), "", logger
      )
      == {}
  )

  # 2. Empty packages_file_path
  assert (
      automate_observation.extract_apks_from_device(
          mock_adb, "", apks_dir, logger
      )
      == {}
  )

  # 3. Non-existent packages_file_path
  assert (
      automate_observation.extract_apks_from_device(
          mock_adb, str(tmp_path / "missing.txt"), apks_dir, logger
      )
      == {}
  )

  # 4. Invalid / unparseable JSON syntax
  corrupt_json_file = tmp_path / "corrupt_packages.txt"
  corrupt_json_file.write_text("{invalid json syntax")
  assert (
      automate_observation.extract_apks_from_device(
          mock_adb, str(corrupt_json_file), apks_dir, logger
      )
      == {}
  )
  logger.error.assert_any_call(
      "Failed to parse JSON from %s.", str(corrupt_json_file)
  )

  # 5. Non-dict top-level JSON value
  non_dict_json_file = tmp_path / "non_dict.txt"
  non_dict_json_file.write_text("[]")
  assert (
      automate_observation.extract_apks_from_device(
          mock_adb, str(non_dict_json_file), apks_dir, logger
      )
      == {}
  )
  logger.error.assert_any_call(
      "Expected a JSON object in %s.", str(non_dict_json_file)
  )

  # 6. JSON with non-list expected key ("packages": None)
  bad_json_file = tmp_path / "bad_packages.txt"
  bad_json_file.write_text(json.dumps({"version": "2.1.0", "packages": None}))
  assert (
      automate_observation.extract_apks_from_device(
          mock_adb, str(bad_json_file), apks_dir, logger
      )
      == {}
  )
  mock_adb.pull.assert_not_called()

  # 7. Package entries missing "name" or "installLocation" are logged and skipped while valid entries extract
  partial_entries_file = tmp_path / "partial_entries.txt"
  partial_entries_file.write_text(
      json.dumps({
          "version": "2.1.0",
          "packages": [
              {"name": "com.missing.location"},
              {"installLocation": "/data/app/missing_name.apk"},
              "not_a_dict_entry",
              {
                  "name": "com.valid.pkg",
                  "installLocation": "/data/app/valid/base.apk",
              },
          ],
      })
  )
  assert (
      automate_observation.extract_apks_from_device(
          mock_adb, str(partial_entries_file), apks_dir, logger
      )
      == {}
  )
  logger.error.assert_any_call(
      "Malformed package entry in %s: %s",
      str(partial_entries_file),
      {"name": "com.missing.location"},
  )
  logger.error.assert_any_call(
      "Malformed package entry in %s: %s",
      str(partial_entries_file),
      {"installLocation": "/data/app/missing_name.apk"},
  )
  logger.error.assert_any_call(
      "Malformed package entry in %s: %s",
      str(partial_entries_file),
      "not_a_dict_entry",
  )
  mock_adb.pull.assert_called_once_with(
      "/data/app/valid/base.apk", str(Path(apks_dir) / "com.valid.pkg")
  )


def test_classify_dir_sequential_numbering_and_failed_extraction_file(
    tmp_path: Path,
):
  """Verifies 000/001 sequential numbering, apks/ creation, and failed_extraction.txt output."""
  fingerprint = "google/lynx/lynx:17/CP2A.260705.006/123456:user/release-keys"
  build_json_content = json.dumps({
      "version": "2.1.0",
      "buildInfo": [{"fingerprint": fingerprint}],
  })
  packages_json_content = json.dumps({
      "version": "2.1.0",
      "packages": [{
          "name": "com.example.unpullable",
          "installLocation": "/system/priv-app/Unpullable/Unpullable.apk",
      }],
  })
  staging_dir = tmp_path / "staging"
  staging_dir.mkdir()

  mock_adb = mock.Mock()
  logger = mock.Mock()

  def fake_pull_success(src: str, dst: str) -> bool:
    if src.endswith("build.txt"):
      Path(dst).write_text(build_json_content)
      return True
    if src == "/sdcard/hubble/results":
      res_dir = Path(dst) / "results"
      res_dir.mkdir(parents=True, exist_ok=True)
      (res_dir / "packages.txt").write_text(packages_json_content)
      return True
    # Fail APK pull so failed_extraction.txt is written
    return False

  mock_adb.pull.side_effect = fake_pull_success
  mock_adb.shell.return_value = False

  # Run 1: extract_apks=False -> allocates 000 without apks/ directory
  dir_000 = automate_observation.classify_dir_using_build_fingerprint(
      mock_adb,
      "/sdcard/hubble/results",
      str(tmp_path),
      extract_apks=False,
      logger=logger,
      tmp_dir=str(staging_dir),
  )
  assert dir_000 == str(tmp_path / fingerprint / "000")
  assert (staging_dir / "device_build.txt").is_file()
  assert Path(dir_000).is_dir()
  assert not (Path(dir_000) / "apks").exists()

  # Run 2: extract_apks=True -> increments to 001, creates apks/, and writes failed_extraction.txt
  dir_001 = automate_observation.classify_dir_using_build_fingerprint(
      mock_adb,
      "/sdcard/hubble/results",
      str(tmp_path),
      extract_apks=True,
      logger=logger,
      tmp_dir=str(staging_dir),
  )
  assert dir_001 == str(tmp_path / fingerprint / "001")
  failed_file = Path(dir_001) / "apks" / "failed_extraction.txt"
  assert failed_file.is_file()
  assert json.loads(failed_file.read_text()) == {
      "com.example.unpullable": "/system/priv-app/Unpullable/Unpullable.apk"
  }

  # Run 3: adb pull of results dir fails -> returns None
  def fake_pull_source_fail(src: str, dst: str) -> bool:
    if src.endswith("build.txt"):
      Path(dst).write_text(build_json_content)
      return True
    return False

  mock_adb.pull.side_effect = fake_pull_source_fail
  dir_002 = automate_observation.classify_dir_using_build_fingerprint(
      mock_adb,
      "/sdcard/hubble/results",
      str(tmp_path),
      extract_apks=False,
      logger=logger,
      tmp_dir=str(staging_dir),
  )
  assert dir_002 is None


@pytest.mark.filterwarnings("error::DeprecationWarning")
def test_classify_dir_adb_backup_fallback(tmp_path: Path):
  """Verifies adb backup decompression, tar extraction, path-traversal rejection, and source_dir move."""
  fingerprint = "google/lynx/lynx:17/CP2A.260705.006/999:user/release-keys"
  build_bytes = json.dumps({
      "version": "2.1.0",
      "buildInfo": [{"fingerprint": fingerprint}],
  }).encode("utf-8")
  packages_bytes = json.dumps({
      "version": "2.1.0",
      "packages": [{
          "name": "com.example.backup_app",
          "installLocation": "/data/app/backup_app/base.apk",
      }],
  }).encode("utf-8")

  # Construct an in-memory tar archive matching Android backup layout:
  # apps/com.uraniborg.hubble/ef/results/{build.txt, packages.txt}
  tar_buffer = io.BytesIO()
  with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
    for rel_name, payload in [
        ("apps/com.uraniborg.hubble/ef/results/build.txt", build_bytes),
        ("apps/com.uraniborg.hubble/ef/results/packages.txt", packages_bytes),
    ]:
      info = tarfile.TarInfo(name=rel_name)
      info.size = len(payload)
      tar.addfile(info, io.BytesIO(payload))

  # Prepend a 24-byte Android backup header: classify_dir_using_build_fingerprint
  # slices compressed_backup_filecontent[24:] before calling zlib.decompress.
  header_24_bytes = b"ANDROID BACKUP\n5\n1\nnone\n"
  assert len(header_24_bytes) == 24
  ab_payload = header_24_bytes + zlib.compress(tar_buffer.getvalue())

  staging_dir = tmp_path / "backup_staging"
  staging_dir.mkdir()
  results_root = tmp_path / "results"

  mock_adb = mock.Mock()
  logger = mock.Mock()

  # Simulate build.txt pull failing so adb_pull_failed=True triggers adb backup
  def fake_pull(src: str, dst: str) -> bool:
    if src.endswith("build.txt"):
      return False
    # Succeed when pulling the APK listed in packages.txt
    if src == "/data/app/backup_app/base.apk":
      return True
    return False

  def fake_backup(ab_path: str, pkg_name: str) -> bool:
    assert pkg_name == automate_observation.HUBBLE_PACKAGE_NAME
    Path(ab_path).write_bytes(ab_payload)
    return True

  mock_adb.pull.side_effect = fake_pull
  mock_adb.backup.side_effect = fake_backup

  out_dir = automate_observation.classify_dir_using_build_fingerprint(
      mock_adb,
      "/sdcard/hubble/results",
      str(results_root),
      extract_apks=True,
      logger=logger,
      tmp_dir=str(staging_dir),
  )

  assert out_dir == str(results_root / fingerprint / "000")
  assert (staging_dir / "hubble_results.ab").is_file()
  assert (staging_dir / "hubble_results.tar").is_file()
  assert (Path(out_dir) / "results" / "build.txt").is_file()
  assert (Path(out_dir) / "results" / "packages.txt").is_file()
  assert (Path(out_dir) / "apks" / "com.example.backup_app").is_dir()

  # Verify tarfile filter="data" blocks "../escape.txt" path traversal
  if hasattr(tarfile, "data_filter"):
    evil_tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=evil_tar_buffer, mode="w") as tar:
      escape_info = tarfile.TarInfo(name="../escape.txt")
      escape_info.size = 6
      tar.addfile(escape_info, io.BytesIO(b"pwned\n"))
    evil_ab_payload = header_24_bytes + zlib.compress(
        evil_tar_buffer.getvalue()
    )
    mock_adb.backup.side_effect = lambda ab_path, _pkg: (
        Path(ab_path).write_bytes(evil_ab_payload) or True
    )
    with pytest.raises(tarfile.FilterError):
      automate_observation.classify_dir_using_build_fingerprint(
          mock_adb,
          "/sdcard/hubble/results",
          str(results_root),
          extract_apks=False,
          logger=logger,
          tmp_dir=str(staging_dir),
      )
    assert not (tmp_path / "escape.txt").exists()

  # Also verify returning None when adb backup itself fails
  mock_adb.backup.side_effect = None
  mock_adb.backup.return_value = False
  assert (
      automate_observation.classify_dir_using_build_fingerprint(
          mock_adb,
          "/sdcard/hubble/results",
          str(results_root),
          extract_apks=False,
          logger=logger,
          tmp_dir=str(staging_dir),
      )
      is None
  )


@mock.patch("automate_observation.classify_dir_using_build_fingerprint")
def test_extract_results_and_apks_destination_normalization_and_validation(
    mock_classify: mock.MagicMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
  """Verifies destination path normalization (/results suffix, trailing slashes, cwd default, and file collision)."""
  mock_adb = mock.Mock()
  logger = mock.Mock()
  mock_classify.return_value = "/final/target/000"
  staging_dir = str(tmp_path / "staging")

  # 1. Destination without "results" basename -> appends "/results" and forwards tmp_dir
  custom_out = tmp_path / "custom_out"
  res = automate_observation.extract_results_and_apks(
      mock_adb,
      "/sdcard/hubble/results",
      str(custom_out),
      logger,
      extract_apks=True,
      pull_preinstalled_only=True,
      tmp_dir=staging_dir,
  )
  expected_dir_1 = str(custom_out / "results")
  assert res == "/final/target/000"
  assert Path(expected_dir_1).is_dir()
  mock_classify.assert_called_once_with(
      mock_adb,
      "/sdcard/hubble/results",
      expected_dir_1,
      True,
      logger,
      pull_preinstalled_only=True,
      tmp_dir=staging_dir,
  )

  # 2. Destination already ending with "results" + trailing slashes -> does not duplicate "/results"
  mock_classify.reset_mock()
  already_results = str(tmp_path / "already" / "results") + "///"
  automate_observation.extract_results_and_apks(
      mock_adb,
      "/sdcard/hubble/results",
      already_results,
      logger,
  )
  expected_dir_2 = str(tmp_path / "already" / "results")
  assert Path(expected_dir_2).is_dir()
  mock_classify.assert_called_once_with(
      mock_adb,
      "/sdcard/hubble/results",
      expected_dir_2,
      False,
      logger,
      pull_preinstalled_only=False,
      tmp_dir="/tmp",
  )

  # 3. Empty destination "" -> defaults to <cwd>/results
  mock_classify.reset_mock()
  cwd_dir = tmp_path / "cwd_workspace"
  cwd_dir.mkdir()
  monkeypatch.chdir(cwd_dir)
  automate_observation.extract_results_and_apks(
      mock_adb,
      "/sdcard/hubble/results",
      "",
      logger,
  )
  expected_dir_3 = str(cwd_dir / "results")
  assert Path(expected_dir_3).is_dir()
  mock_classify.assert_called_once_with(
      mock_adb,
      "/sdcard/hubble/results",
      expected_dir_3,
      False,
      logger,
      pull_preinstalled_only=False,
      tmp_dir="/tmp",
  )

  # 4. Target results_dir exists as a regular file -> logs error and returns None
  mock_classify.reset_mock()
  file_collision_parent = tmp_path / "collision"
  file_collision_parent.mkdir()
  (file_collision_parent / "results").write_text("not a directory")
  invalid_res = automate_observation.extract_results_and_apks(
      mock_adb,
      "/sdcard/hubble/results",
      str(file_collision_parent),
      logger,
  )
  assert invalid_res is None
  logger.error.assert_called_with("Supplied (--output) path is invalid.")
  mock_classify.assert_not_called()


def test_extract_selinux_policies_item_by_item_and_partial_failures(
    tmp_path: Path,
):
  """Verifies selinux/system and selinux/vendor creation and resilient item-by-item pulling."""
  mock_adb = mock.Mock()
  logger = mock.Mock()

  # Simulate /system/etc/selinux ls succeeding, /vendor/etc/selinux ls returning False (partial stat)
  mock_adb.shell.side_effect = [True, False]
  mock_adb.get_result.side_effect = [
      ["plat_sepolicy.cil", "plat_file_contexts"],
      ["vendor_sepolicy.cil"],
  ]

  # Simulate first system policy pull failing, remaining pulls succeeding
  def fake_pull(src: str, dst: str) -> bool:
    if src == "/system/etc/selinux/plat_sepolicy.cil":
      return False
    return True

  mock_adb.pull.side_effect = fake_pull

  automate_observation.extract_selinux_policies(mock_adb, str(tmp_path), logger)

  sys_target = os.path.join(str(tmp_path), "selinux/system/")
  vendor_target = os.path.join(str(tmp_path), "selinux/vendor/")
  assert (tmp_path / "selinux" / "system").is_dir()
  assert (tmp_path / "selinux" / "vendor").is_dir()

  mock_adb.shell.assert_any_call(["ls", "/system/etc/selinux"])
  mock_adb.shell.assert_any_call(["ls", "/vendor/etc/selinux"])

  assert mock_adb.pull.call_count == 3
  mock_adb.pull.assert_any_call(
      "/system/etc/selinux/plat_sepolicy.cil", sys_target
  )
  mock_adb.pull.assert_any_call(
      "/system/etc/selinux/plat_file_contexts", sys_target
  )
  mock_adb.pull.assert_any_call(
      "/vendor/etc/selinux/vendor_sepolicy.cil", vendor_target
  )

  logger.warning.assert_any_call(
      "Failed to fully stat contents in %s", "/vendor/etc/selinux"
  )
  logger.warning.assert_any_call(
      "Failed to pull %s. Continuing...",
      "/system/etc/selinux/plat_sepolicy.cil",
  )


if __name__ == "__main__":
  sys.exit(pytest.main([__file__]))
