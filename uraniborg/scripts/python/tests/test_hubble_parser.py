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

"""Unit tests for hubble_parser.py covering versioning, core files, and package classification."""

import base64
import json
import logging
import os
from pathlib import Path
import sys
from unittest import mock
import pytest

# Ensure uraniborg/scripts/python is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from hubble_parser import HubbleParser


@pytest.fixture
def logger() -> logging.Logger:
  log = logging.getLogger("test_logger")
  log.setLevel(logging.DEBUG)
  return log


@pytest.fixture
def parser(logger: logging.Logger) -> HubbleParser:
  return HubbleParser(logger)


def test_expected_version_constant():
  assert HubbleParser.EXPECTED_VERSION == "2.1.0"


def test_check_version():
  # Exactly 2.1.0 and higher minor versions within major 2.x should pass
  assert HubbleParser.check_version("2.1.0") is True
  assert HubbleParser.check_version("2.1.1") is True
  assert HubbleParser.check_version("2.2.0") is True

  # Higher major versions (3.0.0+) and versions below 2.1.0 are NOT supported
  assert HubbleParser.check_version("3.0.0") is False
  assert HubbleParser.check_version("2.0.1") is False
  assert HubbleParser.check_version("2.0.0") is False
  assert HubbleParser.check_version("1.3.0") is False
  assert HubbleParser.check_version("1.0.0") is False
  assert HubbleParser.check_version("0.9.0") is False

  # Invalid versions
  assert HubbleParser.check_version("invalid") is False
  assert HubbleParser.check_version(None) is False


def test_core_files_dict():
  assert "packages" in HubbleParser.CORE_FILES_DICT
  assert HubbleParser.CORE_FILES_DICT["packages"] == "packages.txt"
  assert "preinstalled-packages" in HubbleParser.CORE_FILES_DICT
  assert (
      HubbleParser.CORE_FILES_DICT["preinstalled-packages"]
      == "preinstalled_packages.txt"
  )


def test_classify_package_factory_preinstalled_apk():
  pkg = {
      "name": "com.android.settings",
      "isPreinstalled": True,
      "isUpdatedSystemApp": False,
      "isApex": False,
      "installLocation": "/system/priv-app/Settings/Settings.apk",
  }
  state = HubbleParser.classify_package(pkg)
  assert state == HubbleParser.PACKAGE_STATE_FACTORY_PREINSTALLED_APK


def test_classify_package_factory_preinstalled_apex_system_partition():
  pkg = {
      "name": "com.android.runtime",
      "isPreinstalled": True,
      "isUpdatedSystemApp": False,
      "isApex": True,
      "installLocation": "/system/apex/com.android.runtime.apex",
  }
  state = HubbleParser.classify_package(pkg)
  assert state == HubbleParser.PACKAGE_STATE_FACTORY_PREINSTALLED_APEX


def test_classify_package_factory_preinstalled_apex_decompressed_capex():
  # Pristine factory compressed CAPEX decompressed at boot
  pkg = {
      "name": "com.android.tzdata",
      "isPreinstalled": True,
      "isUpdatedSystemApp": False,
      "isApex": True,
      "installLocation": (
          "/data/apex/active/com.android.tzdata@340000000.decompressed.apex"
      ),
  }
  state = HubbleParser.classify_package(pkg)
  assert state == HubbleParser.PACKAGE_STATE_FACTORY_PREINSTALLED_APEX

  pkg_decompressed_dir = {
      "name": "com.android.tzdata",
      "isPreinstalled": True,
      "isUpdatedSystemApp": False,
      "isApex": True,
      "installLocation": (
          "/data/apex/decompressed/com.android.tzdata@340000000.decompressed.apex"
      ),
  }
  assert (
      HubbleParser.classify_package(pkg_decompressed_dir)
      == HubbleParser.PACKAGE_STATE_FACTORY_PREINSTALLED_APEX
  )


def test_classify_package_updated_system_app_apk():
  pkg = {
      "name": "com.google.android.apps.maps",
      "isPreinstalled": True,
      "isUpdatedSystemApp": True,
      "isApex": False,
      "installLocation": "/data/app/~~abcdef/com.google.android.apps.maps/base.apk",
  }
  state = HubbleParser.classify_package(pkg)
  assert state == HubbleParser.PACKAGE_STATE_UPDATED_SYSTEM_APP


def test_classify_package_updated_mainline_module_apex():
  pkg = {
      "name": "com.android.conscrypt",
      "isPreinstalled": True,
      "isUpdatedSystemApp": False,  # Note: FLAG_UPDATED_SYSTEM_APP is false for APEX
      "isApex": True,
      "installLocation": "/data/apex/active/com.android.conscrypt@340000005.apex",
  }
  state = HubbleParser.classify_package(pkg)
  assert state == HubbleParser.PACKAGE_STATE_UPDATED_MAINLINE_MODULE


def test_classify_package_user_installed():
  pkg = {
      "name": "org.example.myapp",
      "isPreinstalled": False,
      "isUpdatedSystemApp": False,
      "isApex": False,
      "installLocation": "/data/app/~~12345/org.example.myapp/base.apk",
  }
  state = HubbleParser.classify_package(pkg)
  assert state == HubbleParser.PACKAGE_STATE_USER_INSTALLED


def test_classify_package_unknown_apex_paths_and_non_preinstalled(
    logger: logging.Logger,
):
  # Unrecognized OEM partition path for APEX should classify as UNKNOWN and warn
  unknown_path_pkg = {
      "name": "com.oem.custom.apex",
      "isPreinstalled": True,
      "isUpdatedSystemApp": False,
      "isApex": True,
      "installLocation": "/odm/apex/com.oem.custom.apex",
  }
  with mock.patch.object(logger, "warning") as mock_warn:
    state = HubbleParser.classify_package(unknown_path_pkg, logger=logger)
    assert state == HubbleParser.PACKAGE_STATE_UNKNOWN
    mock_warn.assert_called_once()

  # APEX with isPreinstalled=False should respect isPreinstalled over path heuristics
  non_preinstalled_apex = {
      "name": "com.android.conscrypt",
      "isPreinstalled": False,
      "isUpdatedSystemApp": False,
      "isApex": True,
      "installLocation": "/system/apex/com.android.conscrypt.apex",
  }
  with mock.patch.object(logger, "warning") as mock_warn:
    state = HubbleParser.classify_package(non_preinstalled_apex, logger=logger)
    assert state == HubbleParser.PACKAGE_STATE_UNKNOWN
    mock_warn.assert_called_once()


def test_package_queries_and_filters(parser: HubbleParser):
  packages = [
      {
          "name": "com.android.settings",
          "isPreinstalled": True,
          "isUpdatedSystemApp": False,
          "isApex": False,
          "hasCode": True,
          "installLocation": "/system/priv-app/Settings/Settings.apk",
      },
      {
          "name": "com.android.tzdata",
          "isPreinstalled": True,
          "isUpdatedSystemApp": False,
          "isApex": True,
          "hasCode": True,
          "installLocation": "/data/apex/active/com.android.tzdata@340.decompressed.apex",
      },
      {
          "name": "com.google.android.apps.maps",
          "isPreinstalled": True,
          "isUpdatedSystemApp": True,
          "isApex": False,
          "hasCode": True,
          "installLocation": "/data/app/~~xyz/com.google.android.apps.maps/base.apk",
      },
      {
          "name": "com.android.conscrypt",
          "isPreinstalled": True,
          "isUpdatedSystemApp": False,
          "isApex": True,
          "hasCode": True,
          "installLocation": "/data/apex/active/com.android.conscrypt@340.apex",
      },
      {
          "name": "org.example.userapp",
          "isPreinstalled": False,
          "isUpdatedSystemApp": False,
          "isApex": False,
          "hasCode": True,
          "installLocation": "/data/app/~~usr/org.example.userapp/base.apk",
      },
  ]

  parser.packages = packages

  # Factory preinstalled (APK + APEX)
  factory_all = parser.get_factory_preinstalled_packages(include_apex=True)
  assert factory_all == ["com.android.settings", "com.android.tzdata"]

  # Factory preinstalled (APK only)
  factory_apk_only = parser.get_factory_preinstalled_packages(include_apex=False)
  assert factory_apk_only == ["com.android.settings"]

  # Updated system apps
  updated_apps = parser.get_updated_system_apps()
  assert updated_apps == ["com.google.android.apps.maps"]

  # Updated mainline modules
  updated_mainline = parser.get_updated_mainline_modules()
  assert updated_mainline == ["com.android.conscrypt"]

  # User installed packages
  user_pkgs = parser.get_user_installed_packages()
  assert user_pkgs == ["org.example.userapp"]

  # get_packages_by_state
  assert parser.get_packages_by_state(
      HubbleParser.PACKAGE_STATE_UPDATED_SYSTEM_APP
  ) == ["com.google.android.apps.maps"]


def test_parse_preinstalled_packages(parser: HubbleParser, tmp_path: Path):
  preinstalled_content = {
      "version": "2.1.0",
      "totalPreinstalledPackages": 1,
      "preinstalledPackages": [{
          "name": "com.android.settings",
          "isPreinstalled": True,
          "isUpdatedSystemApp": False,
          "isApex": False,
      }],
  }
  temp_file = tmp_path / "preinstalled_packages.txt"
  temp_file.write_text(json.dumps(preinstalled_content))

  assert parser.parse_preinstalled_packages(str(temp_file)) is True
  assert len(parser.preinstalled_packages) == 1
  assert parser.preinstalled_packages[0]["name"] == "com.android.settings"
  assert parser.get_preinstalled_packages() == ["com.android.settings"]


def test_parse_hubble_output_full_directory(
    parser: HubbleParser, tmp_path: Path
):
  for key, filename in HubbleParser.CORE_FILES_DICT.items():
    file_path = tmp_path / filename
    if filename == "packages.txt":
      content = {
          "version": "2.1.0",
          "totalPackages": 1,
          "packages": [{"name": "com.example", "hasCode": True, "certIds": ["c1"]}],
      }
    elif filename == "preinstalled_packages.txt":
      content = {
          "version": "2.1.0",
          "totalPreinstalledPackages": 1,
          "preinstalledPackages": [{"name": "com.example", "isPreinstalled": True}],
      }
    elif filename == "certificates.txt":
      content = {"version": "2.1.0", "totalCerts": 1, "certs": [{"hash": "c1"}]}
    elif filename == "device_properties.txt":
      content = {
          "version": "2.1.0",
          "b64EncodedDeviceProps": [{
              "encodedDevProps": base64.b64encode(
                  b"ro.build.version.release=15"
              ).decode()
          }],
      }
    elif filename == "build.txt":
      content = {
          "version": "2.1.0",
          "buildInfo": [{
              "apiLevel": 35,
              "fingerprint": "google/pixel/device:15/AP1A/123:user/release-keys",
          }],
      }
    elif filename == "hardware.txt":
      content = {
          "version": "2.1.0",
          "hwInfo": [{"oem": "Google", "model": "Pixel"}],
      }
    file_path.write_text(json.dumps(content))

  assert parser.parse_hubble_output(str(tmp_path)) is True
  assert parser.get_oem() == "Google"
  assert parser.get_api_level() == 35
  assert parser.get_preinstalled_packages() == ["com.example"]


def test_parse_hubble_output_rejects_legacy_pre_2_1_0_directory(
    parser: HubbleParser, logger: logging.Logger, tmp_path: Path
):
  """Verifies 1.0.0 and pre-2.1.0 directories are rejected loudly."""
  # Case 1: Missing preinstalled_packages.txt fails core file check
  for key, filename in HubbleParser.CORE_FILES_DICT.items():
    if filename == "preinstalled_packages.txt":
      continue
    (tmp_path / filename).write_text(json.dumps({"version": "1.0.0"}))
  assert parser.parse_hubble_output(str(tmp_path)) is False

  # Case 2: 1.0.0 version in file is rejected loudly by read_in_json
  legacy_file = tmp_path / "packages.txt"
  legacy_file.write_text(json.dumps({"version": "1.0.0", "packages": []}))
  with mock.patch.object(logger, "error") as mock_error:
    assert parser.read_in_json(str(legacy_file)) is None
    mock_error.assert_called_once()
    assert "NOT supported" in mock_error.call_args[0][0]


def test_state_helpers_when_only_preinstalled_parsed_or_unpopulated(
    parser: HubbleParser, logger: logging.Logger, tmp_path: Path
):
  """Verifies state helpers and _output_version initialization / mismatch handling."""
  assert parser._output_version is None

  # Unpopulated parser (even if self.packages is manually set to "")
  parser.packages = ""
  assert parser.get_factory_preinstalled_packages() == []
  assert parser.get_updated_system_apps() == []
  assert parser.get_updated_mainline_modules() == []
  assert parser.get_user_installed_packages() == []

  # Only preinstalled_packages parsed (self.packages remains empty)
  parser.preinstalled_packages = [
      {
          "name": "com.android.settings",
          "hasCode": True,
          "isPreinstalled": True,
          "isUpdatedSystemApp": False,
          "isApex": False,
          "installLocation": "/system/priv-app/Settings/Settings.apk",
      },
      {
          "name": "com.google.android.apps.maps",
          "hasCode": True,
          "isPreinstalled": True,
          "isUpdatedSystemApp": True,
          "isApex": False,
          "installLocation": "/data/app/~~abc/com.google.android.apps.maps/base.apk",
      },
  ]
  assert parser.get_factory_preinstalled_packages() == ["com.android.settings"]
  assert parser.get_updated_system_apps() == ["com.google.android.apps.maps"]
  with mock.patch.object(logger, "warning") as mock_warn:
    assert parser.get_user_installed_packages() == []
    mock_warn.assert_called_once()

  # Verify _output_version anchors to the first file and warns on mixed versions
  f1 = tmp_path / "f1.txt"
  f2 = tmp_path / "f2.txt"
  f1.write_text(json.dumps({"version": "2.1.0"}))
  f2.write_text(json.dumps({"version": "2.2.0"}))
  parser.read_in_json(str(f1))
  assert parser._output_version == "2.1.0"
  with mock.patch.object(logger, "warning") as mock_warn:
    parser.read_in_json(str(f2))
    assert parser._output_version == "2.1.0"
    mock_warn.assert_called_once()


if __name__ == "__main__":
  sys.exit(pytest.main([__file__]))
