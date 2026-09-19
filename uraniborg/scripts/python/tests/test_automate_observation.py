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

import json
import os
from pathlib import Path
import sys
from unittest import mock
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


@mock.patch("os.path.isfile", return_value=True)
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
  with mock.patch("os.path.isfile", side_effect=[False, True]):
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


@mock.patch("os.path.isfile", return_value=True)
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


@mock.patch("os.path.isfile", return_value=True)
@mock.patch("os.path.exists", return_value=True)
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


@mock.patch("os.path.isfile", return_value=False)
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
  )

  assert result_dir is None
  logger.error.assert_called_once()
  mock_extract_apks.assert_not_called()


if __name__ == "__main__":
  sys.exit(pytest.main([__file__]))
