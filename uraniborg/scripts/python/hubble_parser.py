#!/usr/bin/python3
# Copyright 2020 Uraniborg authors.
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

"""Hubble Output Parser.

This module defines objects and methods that parse outputs from Hubble
observations and expose them as method calls to its consumers.

IMPORTANT: Backwards compatibility with Hubble 1.0.0 (or any version earlier
than 2.1.0) is intentionally NOT supported. Major version bumps break backwards
compatibility by design.
"""

import base64
import json
import os


class HubbleParser:
  """Hubble Parser.

  This class contains methods to read in outputs (assumed to be in JSON form)
  from Hubble observations and parses them into data structures that
  we make directly accessible via attributes or method calls. There are also
  nice helper methods to do printouts when we are measuring baseline and
  curating our baseline packages.

  NOTE: Requires Hubble output schema 2.x (>= 2.1.0). Output from Hubble 1.0.0
  (or any version < 2.1.0) and higher major versions (>= 3.0.0) is NOT supported.
  """
  # Encodes the supported major version and minimum minor version (schema 2.x, >= 2.1.0).
  # Compatibility with < 2.1.0 (including 1.0.0) and >= 3.0.0 is NOT supported.
  EXPECTED_VERSION = "2.1.0"

  # These are core files and their corresponding filenames that Hubble outputs,
  # which may expand in the future.
  # NOTE: It is imperative that for maintenance purposes, the key name does
  # not change in the future.
  CORE_FILES_DICT = {
      "packages": "packages.txt",
      "preinstalled-packages": "preinstalled_packages.txt",
      "certificates": "certificates.txt",
      "device-properties": "device_properties.txt",
      "build": "build.txt",
      "hardware": "hardware.txt"
  }

  PACKAGE_STATE_FACTORY_PREINSTALLED_APK = "FACTORY_PREINSTALLED_APK"
  PACKAGE_STATE_FACTORY_PREINSTALLED_APEX = "FACTORY_PREINSTALLED_APEX"
  PACKAGE_STATE_UPDATED_SYSTEM_APP = "UPDATED_SYSTEM_APP"
  PACKAGE_STATE_UPDATED_MAINLINE_MODULE = "UPDATED_MAINLINE_MODULE"
  PACKAGE_STATE_USER_INSTALLED = "USER_INSTALLED"
  PACKAGE_STATE_UNKNOWN = "UNKNOWN"

  # TODO: Remove SYSTEM_SHARED_UID_SET along with legacy baseline/risk-scoring
  # categorization helpers.
  SYSTEM_SHARED_UID_SET = set([
      "android.uid.system",
      "android.uid.phone",
      "android.uid.log",
      "android.uid.nfc",
      "android.uid.bluetooth",
      "android.uid.shell",
      "android.uid.se",
      "android.uid.networkstack",
  ])

  @staticmethod
  def check_version(version_str):
    try:
      version_str_comps = [int(c) for c in version_str.split(".")]
      expected_version_comps = [
          int(c) for c in HubbleParser.EXPECTED_VERSION.split(".")
      ]
      if len(version_str_comps) < 2:
        return False
      if version_str_comps[0] != expected_version_comps[0]:
        return False
      if version_str_comps[1] < expected_version_comps[1]:
        return False
      return True
    except (ValueError, AttributeError):
      return False

  @staticmethod
  def classify_package(package, logger=None):
    """Classifies an installed package into a distinct installation state.

    Based on Hubble's 6-state classification matrix:
    1. Pristine factory APK: isPreinstalled=true, isUpdatedSystemApp=false, isApex=false
    2. Pristine factory APEX: isPreinstalled=true, isUpdatedSystemApp=false, isApex=true,
       installLocation on system partitions or ending with .decompressed.apex
    3. Updated system app (APK): isPreinstalled=true, isUpdatedSystemApp=true, isApex=false
    4. Updated Mainline module (APEX): isPreinstalled=true, isApex=true,
       installLocation=/data/apex/active/*.apex (not .decompressed.apex)
    5. User-installed (3rd-party): isPreinstalled=false, isUpdatedSystemApp=false, isApex=false
    6. Unknown: isApex=true with unrecognized installLocation or isPreinstalled=false

    Args:
      package: A dict representing a package entry from packages.txt.
      logger: Optional logging.Logger to emit warnings on unrecognized states.

    Returns:
      One of the PACKAGE_STATE_* string constants:
      - PACKAGE_STATE_FACTORY_PREINSTALLED_APK
      - PACKAGE_STATE_FACTORY_PREINSTALLED_APEX
      - PACKAGE_STATE_UPDATED_SYSTEM_APP
      - PACKAGE_STATE_UPDATED_MAINLINE_MODULE
      - PACKAGE_STATE_USER_INSTALLED
      - PACKAGE_STATE_UNKNOWN
    """
    is_preinstalled = package.get("isPreinstalled", False)
    is_updated = bool(package.get("isUpdatedSystemApp", False))
    is_apex = package.get("isApex", False)
    install_location = package.get("installLocation") or ""

    if is_apex:
      # TODO: Move APEX disambiguation into Hubble, which has on-device
      # PackageManager and filesystem visibility.
      # FLAG_UPDATED_SYSTEM_APP is specific to APKs; APEX modules updated via
      # Play / Mainline land in /data/apex/active/... and do not set this flag.
      # Both factory and updated Mainline APEX modules report isPreinstalled=True.
      if not is_preinstalled:
        if logger:
          logger.warning(
              "APEX package %s reports isPreinstalled=False (installLocation=%r); "
              "classifying as UNKNOWN",
              package.get("name", "<unknown>"), install_location)
        return HubbleParser.PACKAGE_STATE_UNKNOWN

      if install_location.endswith(".decompressed.apex") and (
          install_location.startswith(
              ("/data/apex/active/", "/data/apex/decompressed/"))):
        return HubbleParser.PACKAGE_STATE_FACTORY_PREINSTALLED_APEX
      elif install_location.startswith(
          ("/system/", "/vendor/", "/system_ext/", "/product/")):
        return HubbleParser.PACKAGE_STATE_FACTORY_PREINSTALLED_APEX
      elif (install_location.startswith("/data/apex/active/")
            and install_location.endswith(".apex")):
        return HubbleParser.PACKAGE_STATE_UPDATED_MAINLINE_MODULE
      else:
        if logger:
          logger.warning(
              "Unrecognized APEX installLocation %r for package %s; "
              "classifying as UNKNOWN",
              install_location, package.get("name", "<unknown>"))
        return HubbleParser.PACKAGE_STATE_UNKNOWN

    if is_preinstalled:
      if is_updated:
        return HubbleParser.PACKAGE_STATE_UPDATED_SYSTEM_APP
      else:
        return HubbleParser.PACKAGE_STATE_FACTORY_PREINSTALLED_APK
    else:
      return HubbleParser.PACKAGE_STATE_USER_INSTALLED

  def __init__(self, logger, normalize=False):
    self.packages = []
    self.preinstalled_packages = []
    self.certificates = ""
    self.device_properties = ""
    self.build = ""
    self.hardware = ""
    # TODO: Remove legacy risk-scoring and baseline-categorization attributes
    # (scorer, normalize, _platform_signature, _shared_uid_packages) as legacy
    # categorization of Uraniborg results is no longer supported.
    self.scorer = None
    self.normalize = normalize
    self.logger = logger
    self._platform_signature = ""
    self._shared_uid_packages = None
    self._output_version = None

    # do a bit of sanity check
    logger.debug("normalize: %s", self.normalize)

  def parse_hubble_json(self, packages, build, hardware,
                        preinstalled_packages=None):
    """Consumes hubble output as json format.

    Args:
      packages: the json content from packages.txt of hubble output.
      build: the json content from build.txt of hubble output.
      hardware: the json content from hardware.txt of hubble output.
      preinstalled_packages: optional json content from preinstalled_packages.txt.

    Returns:
      True if json content is valid.
      False if not.
    """
    if not packages or not build or not hardware:
      self.logger.error("Missing required hubble output")
      return False
    self.packages = packages
    self.build = build
    self.hardware = hardware
    if preinstalled_packages:
      self.preinstalled_packages = preinstalled_packages
    return True

  def parse_hubble_output(self, directory):
    """Consumes all hubble output and parses them into Python data structure.

    Assuming that hubble output files aren't renamed, this method is able to
    pick up the necessary files to be read into memory and loads them as JSON.

    Args:
      directory: the directory where hubble outputs for a specific observation
                 lives.

    Returns:
      True if every core file is parsed correctly.
      False if any error occurs along the way.
    """
    logger = self.logger
    self._output_version = None
    output_files = os.listdir(directory)
    if not output_files:
      logger.error("%s is empty!", directory)
      return False

    for f in list(HubbleParser.CORE_FILES_DICT.values()):
      if not os.path.exists(os.path.join(directory, f)):
        logger.error("%s not found in %s", f, directory)
        return False

    if not self.parse_packages(os.path.join(
        directory, HubbleParser.CORE_FILES_DICT.get("packages"))):
      logger.error("Failed to parse packages.txt")
      return False
    if not self.parse_preinstalled_packages(os.path.join(
        directory, HubbleParser.CORE_FILES_DICT.get("preinstalled-packages"))):
      logger.error("Failed to parse preinstalled_packages.txt")
      return False
    if not self.parse_certificates(os.path.join(
        directory, HubbleParser.CORE_FILES_DICT.get("certificates"))):
      logger.error("Failed to parse certificates.txt")
      return False
    if not self.parse_device_properties(os.path.join(
        directory, HubbleParser.CORE_FILES_DICT.get("device-properties"))):
      logger.error("Failed to parse device_properties.txt")
      return False
    if not self.parse_build(os.path.join(
        directory, HubbleParser.CORE_FILES_DICT.get("build"))):
      logger.error("Failed to parse build.txt")
      return False
    if not self.parse_hardware(os.path.join(
        directory, HubbleParser.CORE_FILES_DICT.get("hardware"))):
      logger.error("Failed to parse hardware.txt")
      return False
    return True

  def get_oem(self):
    return self.hardware["oem"]

  def get_api_level(self):
    return self.build["apiLevel"]

  # TODO: Remove legacy baseline/whitelist/scoring package categorization
  # methods (get_shared_uid_packages, get_platform_signature,
  # get_platform_packages, print_platform_packages, print_nocode_packages) as
  # legacy categorization of Uraniborg results is no longer supported.
  def get_shared_uid_packages(self):
    if not self._shared_uid_packages:
      platform_signature = self.get_platform_signature()
      self._shared_uid_packages = dict()
      for package in self.packages:
        if platform_signature in package["certIds"]:
          package_shared_uid = package["sharedUserId"]
          if package_shared_uid is not None:
            other_packages = self._shared_uid_packages.get(package_shared_uid)
            if other_packages is None:
              other_packages = [package["name"]]
            else:
              other_packages.append(package["name"])
            self._shared_uid_packages[package_shared_uid] = other_packages

    return self._shared_uid_packages


  def get_platform_signature(self):
    if not self._platform_signature:
      for package in self.packages:
        if package["name"] == "android":
          self._platform_signature = package["certIds"][0]

    return self._platform_signature

  def get_all_packages(self, get_codes_only):
    result = []
    for package in self.packages:
      if not get_codes_only or package["hasCode"]:
        result.append(package["name"])
    return result

  def get_platform_packages(self, get_codes_only):
    result = []
    platform_signature = self.get_platform_signature()
    for package in self.packages:
      if platform_signature in package["certIds"]:
        if not get_codes_only or package["hasCode"]:
          result.append(package["name"])
    return result

  def print_all_packages(self, print_codes_only):
    for package in self.packages:
      if not print_codes_only or package["hasCode"]:
        print("        \"{}\",".format(package["name"]))

  def print_platform_packages(self, print_codes_only):
    platform_signature = self.get_platform_signature()
    for package in self.packages:
      if platform_signature in package["certIds"]:
        if not print_codes_only or package["hasCode"]:
          print("        \"{}\",".format(package["name"]))

  def print_nocode_packages(self):
    for package in self.packages:
      if not package["hasCode"]:
        print("          \"{}\",".format(package["name"]))

  def _get_package_list(self, allow_preinstalled_fallback=True):
    """Returns a validated list of package dicts for iteration."""
    if isinstance(self.packages, list) and self.packages:
      return [p for p in self.packages if isinstance(p, dict)]
    if (allow_preinstalled_fallback and
        isinstance(self.preinstalled_packages, list) and
        self.preinstalled_packages):
      return [p for p in self.preinstalled_packages if isinstance(p, dict)]
    if not allow_preinstalled_fallback and (
        isinstance(self.preinstalled_packages, list) and
        self.preinstalled_packages):
      self.logger.warning(
          "Full package list (packages.txt) is not loaded; "
          "cannot query user-installed packages.")
    return []

  def get_preinstalled_packages(self, get_codes_only=False):
    """Returns a list of preinstalled package names."""
    has_preinstalled = (
        isinstance(self.preinstalled_packages, list) and
        bool(self.preinstalled_packages)
    )
    packages_source = (
        [p for p in self.preinstalled_packages if isinstance(p, dict)]
        if has_preinstalled
        else self._get_package_list(allow_preinstalled_fallback=False)
    )
    result = []
    for package in packages_source:
      if not get_codes_only or package.get("hasCode", True):
        if has_preinstalled or package.get("isPreinstalled", False):
          result.append(package["name"])
    return result

  def get_factory_preinstalled_packages(self, get_codes_only=False,
                                        include_apex=True):
    """Returns a list of pristine factory preinstalled package names."""
    result = []
    for package in self._get_package_list(allow_preinstalled_fallback=True):
      state = self.classify_package(package, self.logger)
      if state == HubbleParser.PACKAGE_STATE_FACTORY_PREINSTALLED_APK or (
          include_apex and state == HubbleParser.PACKAGE_STATE_FACTORY_PREINSTALLED_APEX):
        if not get_codes_only or package.get("hasCode", True):
          result.append(package["name"])
    return result

  def get_updated_system_apps(self, get_codes_only=False):
    """Returns a list of updated system application package names."""
    result = []
    for package in self._get_package_list(allow_preinstalled_fallback=True):
      if self.classify_package(package, self.logger) == HubbleParser.PACKAGE_STATE_UPDATED_SYSTEM_APP:
        if not get_codes_only or package.get("hasCode", True):
          result.append(package["name"])
    return result

  def get_updated_mainline_modules(self):
    """Returns a list of updated APEX/Mainline module package names."""
    result = []
    for package in self._get_package_list(allow_preinstalled_fallback=True):
      if self.classify_package(package, self.logger) == HubbleParser.PACKAGE_STATE_UPDATED_MAINLINE_MODULE:
        result.append(package["name"])
    return result

  def get_user_installed_packages(self, get_codes_only=False):
    """Returns a list of user-installed (third-party) package names."""
    result = []
    for package in self._get_package_list(allow_preinstalled_fallback=False):
      if self.classify_package(package, self.logger) == HubbleParser.PACKAGE_STATE_USER_INSTALLED:
        if not get_codes_only or package.get("hasCode", True):
          result.append(package["name"])
    return result

  def get_packages_by_state(self, state, get_codes_only=False):
    """Returns a list of packages matching a specific classification state."""
    allow_fallback = (state != HubbleParser.PACKAGE_STATE_USER_INSTALLED)
    result = []
    for package in self._get_package_list(allow_preinstalled_fallback=allow_fallback):
      if self.classify_package(package, self.logger) == state:
        if not get_codes_only or package.get("hasCode", True):
          result.append(package["name"])
    return result

  def print_preinstalled_packages(self, print_codes_only=False):
    has_preinstalled = (
        isinstance(self.preinstalled_packages, list) and
        bool(self.preinstalled_packages)
    )
    packages_source = (
        [p for p in self.preinstalled_packages if isinstance(p, dict)]
        if has_preinstalled
        else self._get_package_list(allow_preinstalled_fallback=False)
    )
    for package in packages_source:
      if not print_codes_only or package.get("hasCode", True):
        if has_preinstalled or package.get("isPreinstalled", False):
          print("        \"{}\",".format(package["name"]))

  def print_factory_preinstalled_packages(self, print_codes_only=False,
                                          include_apex=True):
    for package in self._get_package_list(allow_preinstalled_fallback=True):
      state = self.classify_package(package, self.logger)
      if state == HubbleParser.PACKAGE_STATE_FACTORY_PREINSTALLED_APK or (
          include_apex and state == HubbleParser.PACKAGE_STATE_FACTORY_PREINSTALLED_APEX):
        if not print_codes_only or package.get("hasCode", True):
          print("        \"{}\",".format(package["name"]))

  def print_updated_system_apps(self, print_codes_only=False):
    for package in self._get_package_list(allow_preinstalled_fallback=True):
      if self.classify_package(package, self.logger) == HubbleParser.PACKAGE_STATE_UPDATED_SYSTEM_APP:
        if not print_codes_only or package.get("hasCode", True):
          print("        \"{}\",".format(package["name"]))

  def read_in_json(self, path):
    logger = self.logger
    buff = ""
    with open(path, "r") as f_in:
      buff = f_in.read()
    info = json.loads(buff)
    version = info["version"]
    if not HubbleParser.check_version(version):
      expected_major = HubbleParser.EXPECTED_VERSION.split(".")[0]
      logger.error(
          "Hubble output version %s in %s is NOT supported (requires schema "
          "%s.x, >= %s; compatibility with 1.0.0/earlier versions and higher "
          "major versions is not supported).",
          version, path, expected_major, HubbleParser.EXPECTED_VERSION)
      return None
    if self._output_version is None:
      self._output_version = version
    elif self._output_version != version:
      logger.warning(
          "Hubble output version mismatch in %s: %s (expected %s)",
          path, version, self._output_version)
    return info

  def parse_json(self, path, item_type):
    item = self.read_in_json(path)
    if not item:
      return False
    return item[item_type]

  def parse_packages(self, packages_path):
    packages = self.parse_json(packages_path, "packages")
    if not packages:
      return False
    self.packages = packages
    return True

  def parse_preinstalled_packages(self, preinstalled_packages_path):
    preinstalled_packages = self.parse_json(
        preinstalled_packages_path, "preinstalledPackages")
    if not preinstalled_packages:
      return False
    self.preinstalled_packages = preinstalled_packages
    return True

  def parse_certificates(self, certs_path):
    certs = self.parse_json(certs_path, "certs")
    if not certs:
      return False
    self.certificates = certs
    return True

  def parse_device_properties(self, dev_prop_path):
    dev_props = self.parse_json(dev_prop_path, "b64EncodedDeviceProps")
    if not dev_props:
      return False
    encoded_props = dev_props[0]["encodedDevProps"]
    self.device_properties = base64.b64decode(encoded_props)
    return True

  def parse_build(self, build_path):
    build = self.parse_json(build_path, "buildInfo")
    if not build:
      return False
    self.build = build[0]
    return True

  def parse_hardware(self, hw_path):
    hw = self.parse_json(hw_path, "hwInfo")
    if not hw:
      return False
    self.hardware = hw[0]
    return True
