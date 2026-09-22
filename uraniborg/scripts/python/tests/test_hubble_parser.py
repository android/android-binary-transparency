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
import copy
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
  # The floor stays at 2.1.0: the 2.2.0 `signingInfo` object is purely additive,
  # so bumping this would needlessly invalidate every 2.1.0 corpus.
  assert HubbleParser.EXPECTED_VERSION == "2.1.0"
  assert HubbleParser.SIGNING_INFO_MIN_VERSION == "2.2.0"


def test_check_version():
  # Exactly 2.1.0 and higher minor versions within major 2.x should pass
  assert HubbleParser.check_version("2.1.0") is True
  assert HubbleParser.check_version("2.1.1") is True
  assert HubbleParser.check_version("2.2.0") is True
  assert HubbleParser.check_version("2.3.0") is True

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
      "version": "2.2.0",
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
          "version": "2.2.0",
          "totalPackages": 1,
          "packages": [{"name": "com.example", "hasCode": True, "certIds": ["c1"]}],
      }
    elif filename == "preinstalled_packages.txt":
      content = {
          "version": "2.2.0",
          "totalPreinstalledPackages": 1,
          "preinstalledPackages": [{"name": "com.example", "isPreinstalled": True}],
      }
    elif filename == "certificates.txt":
      content = {"version": "2.2.0", "totalCerts": 1, "certs": [{"hash": "c1"}]}
    elif filename == "device_properties.txt":
      content = {
          "version": "2.2.0",
          "b64EncodedDeviceProps": [{
              "encodedDevProps": base64.b64encode(
                  b"ro.build.version.release=15"
              ).decode()
          }],
      }
    elif filename == "build.txt":
      content = {
          "version": "2.2.0",
          "buildInfo": [{
              "apiLevel": 35,
              "fingerprint": "google/pixel/device:15/AP1A/123:user/release-keys",
          }],
      }
    elif filename == "hardware.txt":
      content = {
          "version": "2.2.0",
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
  """Verifies pre-2.1.0 directories are rejected loudly, but 2.1.0 is accepted."""
  # Case 1: Missing preinstalled_packages.txt fails core file check
  for key, filename in HubbleParser.CORE_FILES_DICT.items():
    if filename == "preinstalled_packages.txt":
      continue
    (tmp_path / filename).write_text(json.dumps({"version": "1.0.0"}))
  assert parser.parse_hubble_output(str(tmp_path)) is False

  # Case 2: versions below 2.1.0 in file are rejected loudly by read_in_json
  for legacy_ver in ("1.0.0", "2.0.1"):
    legacy_file = tmp_path / "packages.txt"
    legacy_file.write_text(json.dumps({"version": legacy_ver, "packages": []}))
    with mock.patch.object(logger, "error") as mock_error:
      assert parser.read_in_json(str(legacy_file)) is None
      mock_error.assert_called_once()
      assert "NOT supported" in mock_error.call_args[0][0]


def test_read_in_json_accepts_2_1_0_output_without_signing_info(
    parser: HubbleParser, logger: logging.Logger, tmp_path: Path
):
  """Regression: 2.1.0 corpora must stay readable after the 2.2.0 signingInfo addition.

  `signingInfo` is purely additive and `certIds` is unchanged between 2.1.0 and
  2.2.0, so raising the supported floor would silently orphan every previously
  collected observation.
  """
  legacy_file = tmp_path / "packages.txt"
  legacy_file.write_text(
      json.dumps({
          "version": "2.1.0",
          "packages": [{"name": "android", "certIds": ["cert_platform"]}],
      })
  )
  with mock.patch.object(logger, "error") as mock_error:
    content = parser.read_in_json(str(legacy_file))
    mock_error.assert_not_called()
  assert content is not None
  assert content["packages"][0]["certIds"] == ["cert_platform"]


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
  f1.write_text(json.dumps({"version": "2.2.0"}))
  f2.write_text(json.dumps({"version": "2.3.0"}))
  parser.read_in_json(str(f1))
  assert parser._output_version == "2.2.0"
  with mock.patch.object(logger, "warning") as mock_warn:
    parser.read_in_json(str(f2))
    assert parser._output_version == "2.2.0"
    mock_warn.assert_called_once()


def test_signing_lineage_vs_cosigning_classification_and_helpers(
    parser: HubbleParser, logger: logging.Logger
):
  """Verifies distinction between single signer, v3 key rotation lineage, and co-signed packages."""
  single_signer_pkg = {
      "name": "com.android.settings",
      "hasCode": True,
      "certIds": ["cert_platform"],
      "signingInfo": {
          "hasMultipleSigners": False,
          "hasPastSigningCertificates": False,
          "apkContentsSigners": ["cert_platform"],
          "signingCertificateLineage": ["cert_platform"],
      },
  }
  rotated_lineage_pkg = {
      "name": "com.google.android.apps.messaging",
      "hasCode": True,
      "certIds": ["cert_oldest_v1", "cert_mid_v2", "cert_active_v3"],
      "signingInfo": {
          "hasMultipleSigners": False,
          "hasPastSigningCertificates": True,
          "apkContentsSigners": ["cert_active_v3"],
          "signingCertificateLineage": [
              "cert_oldest_v1",
              "cert_mid_v2",
              "cert_active_v3",
          ],
      },
  }
  cosigned_pkg = {
      "name": "com.example.cosigned",
      "hasCode": True,
      "certIds": ["cert_signer_a", "cert_signer_b"],
      "signingInfo": {
          "hasMultipleSigners": True,
          "hasPastSigningCertificates": False,
          "apkContentsSigners": ["cert_signer_a", "cert_signer_b"],
          "signingCertificateLineage": [],
      },
  }
  missing_signing_info_pkg = {
      "name": "com.example.missing",
      "hasCode": True,
      "certIds": ["cert_legacy"],
  }

  # 1. Classification
  assert (
      HubbleParser.classify_package_signing(single_signer_pkg)
      == HubbleParser.SIGNING_MODE_SINGLE_SIGNER
  )
  assert (
      HubbleParser.classify_package_signing(rotated_lineage_pkg)
      == HubbleParser.SIGNING_MODE_KEY_ROTATION_LINEAGE
  )
  assert (
      HubbleParser.classify_package_signing(cosigned_pkg)
      == HubbleParser.SIGNING_MODE_MULTIPLE_SIGNERS
  )
  # Legacy (< 2.2.0) output has no signingInfo at all. That is a supported,
  # expected state now, so it is reported at debug level rather than as a
  # warning, but it must still classify as UNKNOWN (never guessed from certIds).
  assert not HubbleParser.has_structured_signing_info(missing_signing_info_pkg)
  with mock.patch.object(logger, "debug") as mock_debug:
    assert (
        HubbleParser.classify_package_signing(missing_signing_info_pkg, logger)
        == HubbleParser.SIGNING_MODE_UNKNOWN
    )
    mock_debug.assert_called_once()

  # 2. Active signers vs. Lineage vs. Past certificates
  assert HubbleParser.get_active_signers(single_signer_pkg) == ["cert_platform"]
  assert HubbleParser.get_signing_lineage(single_signer_pkg) == ["cert_platform"]
  assert HubbleParser.get_past_signing_certificates(single_signer_pkg) == []

  assert HubbleParser.get_active_signers(rotated_lineage_pkg) == [
      "cert_active_v3"
  ]
  assert HubbleParser.get_signing_lineage(rotated_lineage_pkg) == [
      "cert_oldest_v1",
      "cert_mid_v2",
      "cert_active_v3",
  ]
  assert HubbleParser.get_past_signing_certificates(rotated_lineage_pkg) == [
      "cert_oldest_v1",
      "cert_mid_v2",
  ]

  assert HubbleParser.get_active_signers(cosigned_pkg) == [
      "cert_signer_a",
      "cert_signer_b",
  ]
  assert HubbleParser.get_signing_lineage(cosigned_pkg) == []
  assert HubbleParser.get_past_signing_certificates(cosigned_pkg) == []

  # 3. Parser query methods
  parser.packages = [
      single_signer_pkg,
      rotated_lineage_pkg,
      cosigned_pkg,
  ]
  assert parser.get_key_rotated_packages() == [
      "com.google.android.apps.messaging"
  ]
  assert parser.get_cosigned_packages() == ["com.example.cosigned"]
  assert parser.get_packages_by_signing_mode(
      HubbleParser.SIGNING_MODE_SINGLE_SIGNER
  ) == ["com.android.settings"]


def test_pre_p_null_rotation_state_classifies_as_unknown(
    logger: logging.Logger,
):
  """API < 28 cannot observe a v3 lineage, so rotation state must not be guessed.

  Hubble emits `hasPastSigningCertificates: null` (not `false`) and an empty
  lineage on pre-P devices. Classifying such a package as SINGLE_SIGNER would be
  an affirmative "never rotated" claim the platform cannot support, and would
  contradict the same never-guess rule applied to legacy 2.1.0 corpora.
  """
  pre_p_pkg = {
      "name": "com.android.settings",
      "hasCode": True,
      "certIds": ["cert_active"],
      "signingInfo": {
          "hasMultipleSigners": False,
          "hasPastSigningCertificates": None,
          "apkContentsSigners": ["cert_active"],
          "signingCertificateLineage": [],
          "platformSignatureMatch": "MATCH",
      },
  }

  with mock.patch.object(logger, "debug") as mock_debug:
    assert (
        HubbleParser.classify_package_signing(pre_p_pkg, logger)
        == HubbleParser.SIGNING_MODE_UNKNOWN
    )
    mock_debug.assert_called_once()

  # No lineage is fabricated from the active signer.
  assert HubbleParser.get_signing_lineage(pre_p_pkg) == []
  assert HubbleParser.get_past_signing_certificates(pre_p_pkg) == []
  # The active signer is still observable, and still usable for platform
  # matching, which is why this remains distinct from "no signingInfo at all".
  assert HubbleParser.has_structured_signing_info(pre_p_pkg)
  assert HubbleParser.get_active_signers(pre_p_pkg) == ["cert_active"]

  # An explicit False (API 28+) must keep classifying as SINGLE_SIGNER.
  api_28_pkg = copy.deepcopy(pre_p_pkg)
  api_28_pkg["signingInfo"]["hasPastSigningCertificates"] = False
  api_28_pkg["signingInfo"]["signingCertificateLineage"] = ["cert_active"]
  assert (
      HubbleParser.classify_package_signing(api_28_pkg)
      == HubbleParser.SIGNING_MODE_SINGLE_SIGNER
  )


def test_pre_p_cosigning_is_still_reported_affirmatively():
  """A pre-P signer count > 1 is observable, so MULTIPLE_SIGNERS is not downgraded.

  Hubble derives `hasMultipleSigners` from the raw `PackageInfo.signatures`
  length *before* digests are computed, so a failed digest cannot silently turn
  a co-signed APK into a single-signer one. Model that here: two declared
  signers, but only one digest survived.
  """
  pre_p_cosigned_pkg = {
      "name": "com.example.cosigned",
      "hasCode": True,
      "certIds": ["cert_signer_a"],
      "signingInfo": {
          "hasMultipleSigners": True,
          "hasPastSigningCertificates": None,
          "apkContentsSigners": ["cert_signer_a"],
          "signingCertificateLineage": [],
      },
  }
  assert (
      HubbleParser.classify_package_signing(pre_p_cosigned_pkg)
      == HubbleParser.SIGNING_MODE_MULTIPLE_SIGNERS
  )


def test_get_platform_signature_and_lineage_matching_on_key_rotation(
    parser: HubbleParser, capsys: pytest.CaptureFixture[str]
):
  """Verifies platform matching intersects the full platform lineage + active signer set."""
  parser.packages = [
      {
          "name": "android",
          "hasCode": True,
          "sharedUserId": "android.uid.system",
          "certIds": ["retired_platform_cert_v1", "active_platform_cert_v2"],
          "signingInfo": {
              "hasMultipleSigners": False,
              "hasPastSigningCertificates": True,
              "apkContentsSigners": ["active_platform_cert_v2"],
              "signingCertificateLineage": [
                  "retired_platform_cert_v1",
                  "active_platform_cert_v2",
              ],
          },
      },
      {
          "name": "com.android.legacy_platform_app",
          "hasCode": True,
          "sharedUserId": "android.uid.system",
          "certIds": ["retired_platform_cert_v1"],
          "signingInfo": {
              "hasMultipleSigners": False,
              "hasPastSigningCertificates": False,
              "apkContentsSigners": ["retired_platform_cert_v1"],
              "signingCertificateLineage": ["retired_platform_cert_v1"],
          },
      },
      {
          "name": "com.android.new_platform_app",
          "hasCode": True,
          "sharedUserId": "android.uid.phone",
          "certIds": ["active_platform_cert_v2"],
          "signingInfo": {
              "hasMultipleSigners": False,
              "hasPastSigningCertificates": False,
              "apkContentsSigners": ["active_platform_cert_v2"],
              "signingCertificateLineage": ["active_platform_cert_v2"],
          },
      },
      {
          "name": "com.example.third_party",
          "hasCode": True,
          "sharedUserId": "com.example.uid",
          "certIds": ["third_party_cert"],
          "signingInfo": {
              "hasMultipleSigners": False,
              "hasPastSigningCertificates": False,
              "apkContentsSigners": ["third_party_cert"],
              "signingCertificateLineage": ["third_party_cert"],
          },
      },
  ]
  assert parser.get_platform_signature() == "active_platform_cert_v2"
  assert parser.get_platform_signatures() == {
      "retired_platform_cert_v1",
      "active_platform_cert_v2",
  }
  assert parser.get_platform_packages(get_codes_only=True) == [
      "android",
      "com.android.legacy_platform_app",
      "com.android.new_platform_app",
  ]
  assert parser.get_shared_uid_packages() == {
      "android.uid.system": ["android", "com.android.legacy_platform_app"],
      "android.uid.phone": ["com.android.new_platform_app"],
  }
  parser.print_platform_packages(print_codes_only=True)
  printed = capsys.readouterr().out
  assert '"com.android.legacy_platform_app"' in printed
  assert '"com.android.new_platform_app"' in printed
  assert '"com.example.third_party"' not in printed

  # Verify cache invalidation when reusing the same HubbleParser instance across
  # a second observation (and verify missing 'android' package caches empty set
  # without re-scanning on subsequent calls).
  parser.packages = [{
      "name": "com.example.only_third_party",
      "hasCode": True,
      "sharedUserId": "android.uid.system",
      "certIds": ["active_platform_cert_v2"],
  }]
  assert parser.get_platform_signatures() == set()
  assert parser._platform_signatures == set()
  assert parser.get_platform_signature() == ""
  assert parser.get_platform_packages(get_codes_only=True) == []
  assert parser.get_shared_uid_packages() == {}


def test_platform_matching_is_directional_on_rotated_away_package(
    parser: HubbleParser,
):
  """A package that rotated AWAY from the platform key is no longer platform-signed.

  Matching must compare the package's ACTIVE signer(s) against the platform's
  full lineage - not full-set against full-set. A symmetric intersection would
  keep matching on the package's own retired platform certificate forever.
  """
  parser.packages = [
      {
          "name": "android",
          "hasCode": True,
          "sharedUserId": "android.uid.system",
          "certIds": ["platform_cert"],
          "signingInfo": {
              "hasMultipleSigners": False,
              "hasPastSigningCertificates": False,
              "apkContentsSigners": ["platform_cert"],
              "signingCertificateLineage": ["platform_cert"],
          },
      },
      {
          # Was platform-signed, has since rotated to its own key.
          "name": "com.example.divested",
          "hasCode": True,
          "sharedUserId": None,
          "certIds": ["platform_cert", "own_cert_v2"],
          "signingInfo": {
              "hasMultipleSigners": False,
              "hasPastSigningCertificates": True,
              "apkContentsSigners": ["own_cert_v2"],
              "signingCertificateLineage": ["platform_cert", "own_cert_v2"],
          },
      },
  ]

  assert parser.get_platform_signatures() == {"platform_cert"}
  # The retired platform cert is still in the package's lineage...
  assert "platform_cert" in HubbleParser.get_package_certificate_set(
      parser.packages[1]
  )
  # ...but it is no longer the active signer, so it is NOT platform-signed.
  assert parser.is_platform_signed(parser.packages[1]) is False
  assert parser.get_platform_packages(get_codes_only=True) == ["android"]


def test_platform_signature_match_is_recorded_but_not_authoritative(
    parser: HubbleParser,
):
  """`platformSignatureMatch` is descriptive only; it must not drive matching.

  `PackageManager.checkSignatures()` is a legacy, pre-rotation-compatible API
  (AOSP `ComputerEngine.checkSignaturesInternal`): it compares *current* signer
  sets for exact equality, then retries with only the *oldest* ancestor of each
  lineage. It never calls `SigningDetails.checkCapability()`, which makes it
  unsound in both directions for "is this platform-signed?".
  """
  parser.packages = [
      {
          "name": "android",
          "hasCode": True,
          "sharedUserId": "android.uid.system",
          "certIds": ["platform_cert"],
          "signingInfo": {
              "hasMultipleSigners": False,
              "hasPastSigningCertificates": False,
              "apkContentsSigners": ["platform_cert"],
              "signingCertificateLineage": ["platform_cert"],
              "platformSignatureMatch": "MATCH",
          },
      },
      {
          # Rotated AWAY from the platform key. checkSignatures reports MATCH via
          # its oldest-ancestor retry, but this package is NOT platform-signed.
          "name": "com.example.divested",
          "hasCode": True,
          "sharedUserId": None,
          "certIds": ["platform_cert", "own_cert_v2"],
          "signingInfo": {
              "hasMultipleSigners": False,
              "hasPastSigningCertificates": True,
              "apkContentsSigners": ["own_cert_v2"],
              "signingCertificateLineage": ["platform_cert", "own_cert_v2"],
              "platformSignatureMatch": "MATCH",
          },
      },
      {
          # Co-signed by the platform key plus another key. checkSignatures
          # reports NO_MATCH (exact set equality fails), but the platform key is
          # an active signer, so it IS platform-signed for our purposes.
          "name": "com.example.cosigned_with_platform",
          "hasCode": True,
          "sharedUserId": None,
          "certIds": ["platform_cert", "partner_cert"],
          "signingInfo": {
              "hasMultipleSigners": True,
              "hasPastSigningCertificates": False,
              "apkContentsSigners": ["platform_cert", "partner_cert"],
              "signingCertificateLineage": [],
              "platformSignatureMatch": "NO_MATCH",
          },
      },
      {
          # PackageManager cannot resolve this one (observed in practice for
          # com.android.privatespace); matching must not depend on the verdict.
          "name": "com.example.unresolvable",
          "hasCode": True,
          "sharedUserId": None,
          "certIds": ["platform_cert"],
          "signingInfo": {
              "hasMultipleSigners": False,
              "hasPastSigningCertificates": False,
              "apkContentsSigners": ["platform_cert"],
              "signingCertificateLineage": ["platform_cert"],
              "platformSignatureMatch": "UNKNOWN_PACKAGE",
          },
      },
  ]

  # The verdict is preserved verbatim for consumers that want it...
  assert [HubbleParser.get_platform_signature_match(p) for p in parser.packages] == [
      "MATCH",
      "MATCH",
      "NO_MATCH",
      "UNKNOWN_PACKAGE",
  ]

  # ...but platform matching ignores it entirely and stays directional.
  assert parser.is_platform_signed(parser.packages[1]) is False  # MATCH, yet no
  assert parser.is_platform_signed(parser.packages[2]) is True   # NO_MATCH, yet yes
  assert parser.is_platform_signed(parser.packages[3]) is True
  assert parser.get_platform_packages(get_codes_only=True) == [
      "android",
      "com.example.cosigned_with_platform",
      "com.example.unresolvable",
  ]


def test_get_platform_signature_match_absent_for_legacy_output():
  """Legacy (< 2.2.0) packages have no recorded verdict."""
  assert HubbleParser.get_platform_signature_match(
      {"name": "android", "certIds": ["platform_cert"]}
  ) is None
  assert HubbleParser.get_platform_signature_match(None) is None


def test_platform_matching_falls_back_for_legacy_2_1_0_packages(
    parser: HubbleParser,
):
  """Legacy (< 2.2.0) packages have no signingInfo but must still match by certIds."""
  parser.packages = [
      {
          "name": "android",
          "hasCode": True,
          "sharedUserId": "android.uid.system",
          "certIds": ["platform_cert"],
      },
      {
          "name": "com.android.systemui",
          "hasCode": True,
          "sharedUserId": "android.uid.system",
          "certIds": ["platform_cert"],
      },
      {
          "name": "com.example.third_party",
          "hasCode": True,
          "sharedUserId": None,
          "certIds": ["third_party_cert"],
      },
  ]

  assert not HubbleParser.has_structured_signing_info(parser.packages[0])
  assert parser.get_platform_signature() == "platform_cert"
  assert parser.get_platform_packages(get_codes_only=True) == [
      "android",
      "com.android.systemui",
  ]
  assert parser.get_shared_uid_packages() == {
      "android.uid.system": ["android", "com.android.systemui"],
  }


if __name__ == "__main__":
  sys.exit(pytest.main([__file__]))
