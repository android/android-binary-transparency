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

"""Unit tests for inclusion_proof_check.py."""

import json
import logging
import os
from pathlib import Path
import subprocess
import sys
from unittest import mock
import pytest

# Ensure uraniborg/scripts/python is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import inclusion_proof_check


@pytest.fixture
def logger() -> logging.Logger:
  log = logging.getLogger("test_logger")
  log.setLevel(logging.DEBUG)
  return log


@mock.patch("subprocess.run")
def test_prefetch_log_entries_default(
    mock_run: mock.MagicMock, logger: logging.Logger
):
  mock_run.return_value = mock.Mock(returncode=0)

  result = inclusion_proof_check.prefetch_log_entries("/path/to/verifier", logger)

  assert result is True
  mock_run.assert_called_once_with(
      [
          "/path/to/verifier",
          "--log_type=google_1p_apk",
          "--fetch_entries",
          "--concurrency=16",
      ],
      check=False,
      timeout=600,
  )


@mock.patch("subprocess.run")
def test_prefetch_log_entries_custom_cache_and_concurrency(
    mock_run: mock.MagicMock, logger: logging.Logger
):
  mock_run.return_value = mock.Mock(returncode=0)

  result = inclusion_proof_check.prefetch_log_entries(
      "/path/to/verifier",
      logger,
      cache_dir="/custom/cache",
      concurrency=8,
  )

  assert result is True
  mock_run.assert_called_once_with(
      [
          "/path/to/verifier",
          "--log_type=google_1p_apk",
          "--fetch_entries",
          "--concurrency=8",
          "--cache_dir=/custom/cache",
      ],
      check=False,
      timeout=600,
  )


@mock.patch("subprocess.run")
def test_prefetch_log_entries_failure_nonzero_returncode(
    mock_run: mock.MagicMock, logger: logging.Logger
):
  mock_run.return_value = mock.Mock(returncode=1)

  with mock.patch.object(logger, "warning") as mock_warn:
    result = inclusion_proof_check.prefetch_log_entries("/path/to/verifier", logger)

  assert result is False
  mock_warn.assert_called_once()


@mock.patch(
    "subprocess.run",
    side_effect=subprocess.TimeoutExpired(cmd="verifier", timeout=600),
)
def test_prefetch_log_entries_timeout(
    mock_run: mock.MagicMock, logger: logging.Logger
):
  with mock.patch.object(logger, "warning") as mock_warn:
    result = inclusion_proof_check.prefetch_log_entries("/path/to/verifier", logger)

  assert result is False
  mock_warn.assert_called_once()


@mock.patch("subprocess.run", side_effect=FileNotFoundError("verifier not found"))
def test_prefetch_log_entries_file_not_found(
    mock_run: mock.MagicMock, logger: logging.Logger
):
  with mock.patch.object(logger, "error") as mock_error:
    result = inclusion_proof_check.prefetch_log_entries("/bad/verifier", logger)

  assert result is False
  mock_error.assert_called_once()


@mock.patch("subprocess.run")
def test_run_verifier_with_cache_dir(
    mock_run: mock.MagicMock, tmp_path: Path, logger: logging.Logger
):
  mock_run.return_value = mock.Mock(
      returncode=0,
      stdout="OK. inclusion check success!",
      stderr="",
  )
  payload_file = tmp_path / "payload.txt"
  payload_file.write_text("hash\nSHA256(APK)\ncom.example\n1\n")

  verified = inclusion_proof_check.run_verifier(
      "/path/to/verifier",
      str(payload_file),
      logger,
      cache_dir="/custom/cache",
  )

  assert verified is True
  mock_run.assert_called_once_with(
      [
          "/path/to/verifier",
          f"--payload_path={payload_file}",
          "--log_type=google_1p_apk",
          "--cache_dir=/custom/cache",
      ],
      capture_output=True,
      text=True,
      check=False,
  )


@mock.patch("subprocess.run")
def test_perform_inclusion_proof_check_with_prefetch(
    mock_run: mock.MagicMock, tmp_path: Path, logger: logging.Logger
):
  def side_effect(cmd, **kwargs):
    if "--fetch_entries" in cmd:
      return mock.Mock(returncode=0, stdout="prefetched", stderr="")
    return mock.Mock(
        returncode=0,
        stdout="OK. inclusion check success!",
        stderr="",
    )

  mock_run.side_effect = side_effect

  packages_file = tmp_path / "packages.txt"
  packages_file.write_text(json.dumps({
      "packages": [{
          "name": "com.google.android.gm",
          "versionCode": 123,
          "splits": [{"hash": "abc123hash"}],
      }]
  }))

  success = inclusion_proof_check.perform_inclusion_proof_check(
      "/path/to/verifier",
      str(packages_file),
      logger,
      cache_dir="/tmp/cache",
      concurrency=32,
      timeout=45,
      prefetch=True,
  )

  assert success is True
  assert mock_run.call_count == 2

  prefetch_cmd = mock_run.call_args_list[0][0][0]
  assert "--fetch_entries" in prefetch_cmd
  assert "--concurrency=32" in prefetch_cmd
  assert "--cache_dir=/tmp/cache" in prefetch_cmd
  assert mock_run.call_args_list[0].kwargs["timeout"] == 45

  verify_cmd = mock_run.call_args_list[1][0][0]
  assert "--log_type=google_1p_apk" in verify_cmd
  assert "--cache_dir=/tmp/cache" in verify_cmd

  output_file = tmp_path / inclusion_proof_check.OUTPUT_FILENAME
  assert output_file.exists()
  result_json = json.loads(output_file.read_text())
  assert result_json["packages"][0]["splits"][0]["inclusion_proof_verified"] is True


@mock.patch("subprocess.run")
def test_perform_inclusion_proof_check_prefetch_disabled(
    mock_run: mock.MagicMock, tmp_path: Path, logger: logging.Logger
):
  mock_run.return_value = mock.Mock(
      returncode=0,
      stdout="OK. inclusion check success!",
      stderr="",
  )

  packages_file = tmp_path / "packages.txt"
  packages_file.write_text(json.dumps({
      "packages": [{
          "name": "com.google.android.gm",
          "versionCode": 123,
          "splits": [{"hash": "abc123hash"}],
      }]
  }))

  success = inclusion_proof_check.perform_inclusion_proof_check(
      "/path/to/verifier",
      str(packages_file),
      logger,
      cache_dir="/tmp/cache",
      prefetch=False,
  )

  assert success is True
  assert mock_run.call_count == 1
  verify_cmd = mock_run.call_args_list[0][0][0]
  assert "--fetch_entries" not in verify_cmd
  assert "--log_type=google_1p_apk" in verify_cmd

  output_file = tmp_path / inclusion_proof_check.OUTPUT_FILENAME
  assert output_file.exists()
  result_json = json.loads(output_file.read_text())
  assert result_json["packages"][0]["splits"][0]["inclusion_proof_verified"] is True


@mock.patch("subprocess.run")
def test_perform_inclusion_proof_check_fail_open_on_prefetch_failure(
    mock_run: mock.MagicMock, tmp_path: Path, logger: logging.Logger
):
  def side_effect(cmd, **kwargs):
    if "--fetch_entries" in cmd:
      return mock.Mock(returncode=1, stdout="", stderr="prefetch network timeout")
    return mock.Mock(
        returncode=0,
        stdout="OK. inclusion check success!",
        stderr="",
    )

  mock_run.side_effect = side_effect

  packages_file = tmp_path / "packages.txt"
  packages_file.write_text(json.dumps({
      "packages": [{
          "name": "com.google.android.gm",
          "versionCode": 123,
          "splits": [{"hash": "abc123hash"}],
      }]
  }))

  success = inclusion_proof_check.perform_inclusion_proof_check(
      "/path/to/verifier",
      str(packages_file),
      logger,
      prefetch=True,
  )

  assert success is True
  assert mock_run.call_count == 2

  output_file = tmp_path / inclusion_proof_check.OUTPUT_FILENAME
  assert output_file.exists()
  result_json = json.loads(output_file.read_text())
  assert result_json["packages"][0]["splits"][0]["inclusion_proof_verified"] is True


@mock.patch("subprocess.run")
def test_perform_inclusion_proof_check_skips_prefetch_on_invalid_packages_file(
    mock_run: mock.MagicMock, tmp_path: Path, logger: logging.Logger
):
  packages_file = tmp_path / "packages.txt"
  packages_file.write_text(json.dumps({"packages": {"not": "a list"}}))

  success = inclusion_proof_check.perform_inclusion_proof_check(
      "/path/to/verifier",
      str(packages_file),
      logger,
      prefetch=True,
  )

  assert success is False
  mock_run.assert_not_called()


@mock.patch("subprocess.run")
def test_perform_inclusion_proof_check_empty_packages_list_skips_prefetch_and_succeeds(
    mock_run: mock.MagicMock, tmp_path: Path, logger: logging.Logger
):
  packages_file = tmp_path / "packages.txt"
  packages_file.write_text(json.dumps({"packages": []}))

  success = inclusion_proof_check.perform_inclusion_proof_check(
      "/path/to/verifier",
      str(packages_file),
      logger,
      prefetch=True,
  )

  assert success is True
  mock_run.assert_not_called()

  output_file = tmp_path / inclusion_proof_check.OUTPUT_FILENAME
  assert output_file.exists()
  result_json = json.loads(output_file.read_text())
  assert result_json == {
      "source": "packages.txt",
      "totalPackages": 0,
      "packages": [],
  }


@mock.patch("subprocess.run")
def test_perform_inclusion_proof_check_with_preinstalled_packages_and_metadata(
    mock_run: mock.MagicMock, tmp_path: Path, logger: logging.Logger
):
  def side_effect(cmd, **kwargs):
    if "--fetch_entries" in cmd:
      return mock.Mock(returncode=0, stdout="prefetched", stderr="")
    return mock.Mock(
        returncode=0,
        stdout="OK. inclusion check success!",
        stderr="",
    )

  mock_run.side_effect = side_effect

  # Also create an existing full-run output file to verify it is NOT overwritten
  existing_full_output = tmp_path / inclusion_proof_check.OUTPUT_FILENAME
  existing_full_output.write_text(json.dumps({
      "source": "packages.txt",
      "totalPackages": 401,
      "packages": [],
  }))

  preinstalled_file = tmp_path / "preinstalled_packages.txt"
  preinstalled_file.write_text(json.dumps({
      "version": "2.1.0",
      "totalPreinstalledPackages": 2,
      "preinstalledPackages": [
          {
              "name": "com.android.settings",
              "versionCode": 100,
              "isPreinstalled": True,
              "isUpdatedSystemApp": False,
              "isApex": False,
              "splits": [{"hash": "hash_settings"}],
          },
          {
              "name": "com.google.android.apps.maps",
              "versionCode": 200,
              "isPreinstalled": True,
              "isUpdatedSystemApp": True,
              "isApex": False,
              "splits": [{"hash": "hash_maps"}],
          },
      ],
  }))

  success = inclusion_proof_check.perform_inclusion_proof_check(
      "/path/to/verifier",
      str(preinstalled_file),
      logger,
      prefetch=True,
      preinstalled_only=True,
  )

  assert success is True
  # Full-run output artifact remains intact
  assert json.loads(existing_full_output.read_text())["totalPackages"] == 401

  output_file = tmp_path / inclusion_proof_check.PREINSTALLED_OUTPUT_FILENAME
  assert output_file.exists()
  result_json = json.loads(output_file.read_text())
  assert result_json["source"] == "preinstalled_packages.txt"
  assert result_json["totalPackages"] == 2
  assert len(result_json["packages"]) == 2
  pkg0 = result_json["packages"][0]
  assert pkg0["name"] == "com.android.settings"
  assert pkg0["isPreinstalled"] is True
  assert pkg0["isUpdatedSystemApp"] is False
  assert pkg0["isApex"] is False
  assert pkg0["splits"][0]["inclusion_proof_verified"] is True

  pkg1 = result_json["packages"][1]
  assert pkg1["name"] == "com.google.android.apps.maps"
  assert pkg1["isPreinstalled"] is True
  assert pkg1["isUpdatedSystemApp"] is True
  assert pkg1["isApex"] is False
  assert pkg1["splits"][0]["inclusion_proof_verified"] is True


def test_main_exits_nonzero_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
  missing_file = tmp_path / "does_not_exist.txt"
  monkeypatch.setattr(
      sys,
      "argv",
      [
          "inclusion_proof_check.py",
          f"--packages_file={missing_file}",
          "--verifier_path=/path/to/verifier",
      ],
  )
  with pytest.raises(SystemExit) as exc_info:
    inclusion_proof_check.main()
  assert exc_info.value.code == 1


if __name__ == "__main__":
  sys.exit(pytest.main([__file__]))
