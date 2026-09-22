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

Within the supported 2.x range, minor versions are additive and are read on a
best-effort basis. In particular, the `signingInfo` object introduced in 2.2.0
is absent from 2.1.0 output; helpers that depend on it degrade gracefully (see
`has_structured_signing_info`) rather than rejecting the observation, so that
previously collected 2.1.0 corpora remain readable and comparable over time.
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
  Schema 2.2.0 adds the `signingInfo` object; 2.1.0 output remains supported and
  is handled via documented legacy fallbacks.
  """
  # Encodes the supported major version and minimum minor version (schema 2.x, >= 2.1.0).
  # Compatibility with < 2.1.0 (including 1.0.0) and >= 3.0.0 is NOT supported.
  #
  # NOTE: Deliberately NOT bumped to 2.2.0. The 2.2.0 `signingInfo` object is purely
  # additive and leaves `certIds` byte-for-byte unchanged, so raising this floor would
  # invalidate every previously collected 2.1.0 observation for no correctness benefit.
  # Only raise this for a genuinely breaking schema change.
  EXPECTED_VERSION = "2.1.0"

  # The minor version that introduced the structured `signingInfo` object. Used only to
  # document/describe capability, never to reject an observation.
  SIGNING_INFO_MIN_VERSION = "2.2.0"

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

  SIGNING_MODE_SINGLE_SIGNER = "SINGLE_SIGNER"
  SIGNING_MODE_KEY_ROTATION_LINEAGE = "KEY_ROTATION_LINEAGE"
  SIGNING_MODE_MULTIPLE_SIGNERS = "MULTIPLE_SIGNERS"
  SIGNING_MODE_UNKNOWN = "UNKNOWN"

  # The Android framework package, whose signing identity defines "platform-signed".
  PLATFORM_PACKAGE_NAME = "android"

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
  def has_structured_signing_info(package):
    """Returns True if the package carries the structured `signingInfo` object.

    The `signingInfo` object was introduced in Hubble schema 2.2.0. Observations
    collected with 2.1.0 do not have it, and for those the flat `certIds` list is
    inherently ambiguous: it holds either a key rotation lineage OR a set of
    active co-signers, with no way to tell which. Callers that need to reason
    about signing semantics should check this first and treat a False result as
    "unknown" rather than assuming a single signer.

    Args:
      package: A dict representing a package entry from packages.txt.

    Returns:
      True if structured signing metadata is present, False for legacy output.
    """
    return (isinstance(package, dict) and
            isinstance(package.get("signingInfo"), dict))

  @staticmethod
  def get_active_signers(package):
    """Returns the currently active signing certificate digest(s) for a package.

    For single-signer packages (with or without a key rotation lineage), this
    returns a 1-element list containing the current active signer. For co-signed
    packages (hasMultipleSigners=True), this returns all active co-signers.

    LEGACY (schema < 2.2.0): when `signingInfo` is absent, this falls back to the
    flat `certIds` list. That list is ambiguous - for a rotated package it is the
    full lineage (oldest first), not just the active signer - so the result is an
    over-approximation. Use `has_structured_signing_info()` to detect this case.

    Args:
      package: A dict representing a package entry from packages.txt.

    Returns:
      A list of SHA-256 hex digest strings for the active signer(s).
    """
    if not isinstance(package, dict):
      return []
    signing_info = package.get("signingInfo")
    if isinstance(signing_info, dict):
      active = signing_info.get("apkContentsSigners")
      if isinstance(active, list) and active:
        return list(active)
      # apkContentsSigners should always be populated in 2.2.0+, but if every
      # digest failed to compute on device, recover the active signer from the
      # tail of the lineage (Android orders it oldest -> current).
      if not signing_info.get("hasMultipleSigners", False):
        lineage = signing_info.get("signingCertificateLineage")
        if isinstance(lineage, list) and lineage:
          return [lineage[-1]]
      return []
    cert_ids = package.get("certIds")
    if isinstance(cert_ids, list):
      return list(cert_ids)
    return []

  @staticmethod
  def get_signing_lineage(package):
    """Returns the ordered signing certificate lineage for a package.

    When a package is not co-signed (hasMultipleSigners=False), returns the
    certificate digests ordered from oldest ancestor at index 0 to the current
    active signer at index -1. When a package is co-signed by multiple signers
    (hasMultipleSigners=True), returns an empty list because multi-signer APKs
    do not have a signing certificate rotation lineage.

    LEGACY (schema < 2.2.0): returns [] because pre-2.2.0 output cannot express a
    lineage unambiguously. This is deliberately NOT backfilled from `certIds`, so
    that "no lineage" is never confused with "lineage unknown".

    API < 28: also returns [], because the platform exposes no v3 lineage API.
    Hubble deliberately does not fabricate one from the active signers; use
    `classify_package_signing()`, which reports UNKNOWN for that case.

    Args:
      package: A dict representing a package entry from packages.txt.

    Returns:
      A list of SHA-256 hex digest strings ordered [oldest_ancestor, ..., current_signer],
      or [] if co-signed or unavailable.
    """
    if not HubbleParser.has_structured_signing_info(package):
      return []
    signing_info = package["signingInfo"]
    if signing_info.get("hasMultipleSigners", False):
      return []
    lineage = signing_info.get("signingCertificateLineage")
    if isinstance(lineage, list):
      return list(lineage)
    return []

  @staticmethod
  def get_past_signing_certificates(package):
    """Returns historical ancestor signing certificates excluding the active signer.

    Args:
      package: A dict representing a package entry from packages.txt.

    Returns:
      A list of retired/past ancestor SHA-256 certificate digests ordered from
      oldest ancestor to most recent predecessor, or [] if the package has not
      undergone key rotation or is co-signed.
    """
    lineage = HubbleParser.get_signing_lineage(package)
    if len(lineage) > 1:
      return lineage[:-1]
    return []

  @staticmethod
  def classify_package_signing(package, logger=None):
    """Classifies a package's signing configuration (lineage vs. co-signing).

    Distinguishes between:
    1. SINGLE_SIGNER: Signed by a single certificate with no key rotation history
       (hasMultipleSigners=False, hasPastSigningCertificates=False).
    2. KEY_ROTATION_LINEAGE: Signed by a single active certificate with one or
       more past ancestor certificates in its v3 signing lineage
       (hasMultipleSigners=False, hasPastSigningCertificates=True).
    3. MULTIPLE_SIGNERS: Co-signed simultaneously by multiple active signers
       (hasMultipleSigners=True).
    4. UNKNOWN: The signing configuration cannot be determined. This covers:
       (a) every package in a legacy (schema < 2.2.0) observation, where
       `signingInfo` does not exist and `certIds` alone cannot distinguish a
       rotation lineage from a set of co-signers; (b) a package collected on
       API < 28, where PackageManager exposes no v3 lineage API and Hubble
       therefore emits `hasPastSigningCertificates: null` - "not rotated" is
       unobservable there, not false; (c) missing or malformed metadata.
       Co-signing is still reported affirmatively on API < 28, since the
       signer count itself is observable.

    Args:
      package: A dict representing a package entry from packages.txt.
      logger: Optional logging.Logger to emit warnings on missing signingInfo.

    Returns:
      One of the SIGNING_MODE_* string constants.
    """
    if not isinstance(package, dict):
      return HubbleParser.SIGNING_MODE_UNKNOWN

    if not HubbleParser.has_structured_signing_info(package):
      if logger:
        logger.debug(
            "Package %s has no structured signingInfo (legacy Hubble output "
            "< %s); classifying signing mode as UNKNOWN",
            package.get("name", "<unknown>"),
            HubbleParser.SIGNING_INFO_MIN_VERSION)
      return HubbleParser.SIGNING_MODE_UNKNOWN
    signing_info = package["signingInfo"]

    has_multiple = bool(signing_info.get("hasMultipleSigners", False))
    # Tri-state: Hubble emits null on API < 28, where PackageManager exposes no
    # v3 lineage API and "not rotated" is therefore unobservable, not false.
    has_past_raw = signing_info.get("hasPastSigningCertificates")
    rotation_state_known = isinstance(has_past_raw, bool)
    has_past = has_past_raw is True
    active_signers = signing_info.get("apkContentsSigners")
    if not isinstance(active_signers, list):
      active_signers = []
    lineage = HubbleParser.get_signing_lineage(package)

    if not active_signers and not lineage:
      if logger:
        logger.warning(
            "Package %s has empty signingInfo certificates; "
            "classifying signing mode as UNKNOWN",
            package.get("name", "<unknown>"))
      return HubbleParser.SIGNING_MODE_UNKNOWN

    # Checked first: a signer count > 1 is directly observable on every API
    # level, so co-signing is affirmative even when rotation state is not.
    if has_multiple or len(active_signers) > 1:
      return HubbleParser.SIGNING_MODE_MULTIPLE_SIGNERS

    if has_past or len(lineage) > 1:
      return HubbleParser.SIGNING_MODE_KEY_ROTATION_LINEAGE

    if not rotation_state_known:
      if logger:
        logger.debug(
            "Package %s has an unobservable key rotation state (API < 28); "
            "classifying signing mode as UNKNOWN",
            package.get("name", "<unknown>"))
      return HubbleParser.SIGNING_MODE_UNKNOWN

    if len(active_signers) == 1 or len(lineage) == 1:
      return HubbleParser.SIGNING_MODE_SINGLE_SIGNER

    return HubbleParser.SIGNING_MODE_UNKNOWN

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

  @staticmethod
  def get_package_certificate_set(package):
    """Returns every signing certificate ever associated with a package.

    This is the union of the package's rotation lineage, its active signer(s),
    and the flat `certIds` list, i.e. both current AND retired certificates.

    WARNING: This set is only meaningful as the *trust anchor* side of a
    comparison (e.g. "the set of certificates that identify the platform"). Do
    NOT use it for the candidate package side: a package that has rotated AWAY
    from a trusted key still contains that key in its lineage, so intersecting
    two full certificate sets would treat it as still trusted. For the candidate
    side use `get_active_signers()`; see `is_platform_signed()`.
    """
    if not isinstance(package, dict):
      return set()
    certs = (
        set(HubbleParser.get_signing_lineage(package))
        | set(HubbleParser.get_active_signers(package))
    )
    cert_ids = package.get("certIds")
    if isinstance(cert_ids, list):
      certs.update(cert_ids)
    return certs

  def __init__(self, logger, normalize=False):
    self._packages = []
    self.preinstalled_packages = []
    self.certificates = ""
    self.device_properties = ""
    self.build = ""
    self.hardware = ""
    # TODO: Remove legacy risk-scoring and baseline-categorization attributes
    # (scorer, normalize, _platform_signature, _platform_signatures,
    # _shared_uid_packages) as legacy categorization of Uraniborg results is no
    # longer supported.
    self.scorer = None
    self.normalize = normalize
    self.logger = logger
    self._platform_signature = ""
    self._platform_signatures = None
    self._shared_uid_packages = None
    self._output_version = None

    # do a bit of sanity check
    logger.debug("normalize: %s", self.normalize)

  @property
  def packages(self):
    return self._packages

  @packages.setter
  def packages(self, value):
    self._packages = value
    self._platform_signature = ""
    self._platform_signatures = None
    self._shared_uid_packages = None

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
    self._platform_signature = ""
    self._platform_signatures = None
    self._shared_uid_packages = None
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
  # methods (get_package_certificate_set, get_shared_uid_packages,
  # get_platform_signatures, get_platform_signature, get_platform_packages,
  # print_platform_packages, print_nocode_packages) as legacy categorization of
  # Uraniborg results is no longer supported.
  def get_shared_uid_packages(self):
    if not self._shared_uid_packages:
      self._shared_uid_packages = dict()
      for package in self.packages:
        if self.is_platform_signed(package):
          package_shared_uid = package["sharedUserId"]
          if package_shared_uid is not None:
            other_packages = self._shared_uid_packages.get(package_shared_uid)
            if other_packages is None:
              other_packages = [package["name"]]
            else:
              other_packages.append(package["name"])
            self._shared_uid_packages[package_shared_uid] = other_packages

    return self._shared_uid_packages

  def get_platform_signatures(self):
    """Returns the platform's full signing identity (lineage union active signers).

    This is the trust-anchor set: every certificate the `android` framework
    package has ever been signed by, so that a platform key rotation does not
    orphan system packages still signed with a retired platform certificate.
    """
    if self._platform_signatures is None:
      self._platform_signatures = set()
      for package in self.packages:
        if package["name"] == HubbleParser.PLATFORM_PACKAGE_NAME:
          self._platform_signatures = self.get_package_certificate_set(package)
          break

    return self._platform_signatures

  @staticmethod
  def get_platform_signature_match(package):
    """Returns the recorded `PackageManager.checkSignatures(pkg, "android")` verdict.

    Present only in Hubble >= 2.2.0 output. This is descriptive metadata: it is
    what `PackageManager` itself would report to an app, which is useful when
    reasoning about legacy callers of that API. It is NOT used to decide platform
    signing - see `is_platform_signed()` for why.

    Args:
      package: A dict representing a package entry from packages.txt.

    Returns:
      One of "MATCH", "NO_MATCH", "NEITHER_SIGNED", "FIRST_NOT_SIGNED",
      "SECOND_NOT_SIGNED", "UNKNOWN_PACKAGE", "UNKNOWN", or None if unavailable.
    """
    if not HubbleParser.has_structured_signing_info(package):
      return None
    return package["signingInfo"].get("platformSignatureMatch")

  def is_platform_signed(self, package):
    """Returns True if `package` shares a signing identity with the platform.

    Uses a directional comparison: the package's *active* signer(s) against the
    platform's *full* lineage (`get_platform_signatures()`). It deliberately does
    NOT consider the package's own retired certificates, so a package that has
    rotated away from the platform key is correctly no longer treated as
    platform-signed.

    Why `signingInfo.platformSignatureMatch` is deliberately NOT used here:

    `PackageManager.checkSignatures()` is a legacy, pre-rotation-compatible API,
    not a capability-aware trust decision. Per AOSP
    `ComputerEngine.checkSignaturesInternal()` it (1) compares the two packages'
    *current* signer sets for exact set equality, then (2) on failure, if either
    side has a lineage, retries using only the *oldest* ancestor of each. It
    never calls `SigningDetails.checkCapability()`. That makes it unsound in both
    directions for this question:

      - False positive: a package that rotated AWAY from the platform key still
        reports MATCH, because step (2) compares the retired platform cert.
        Trusting it would reintroduce exactly the bug this method avoids.
      - False negative: a package co-signed by the platform key PLUS another key
        reports NO_MATCH, because step (1) demands exact set equality.

    Use `get_platform_signature_match()` if you specifically want that verdict.

    KNOWN LIMITATION: neither approach can see the per-ancestor
    `SigningDetails.CertCapabilities` flags (`PERMISSION`, `SHARED_USER_ID`) that
    a key rotation may revoke. The framework evaluates those in its shared-UID
    join logic and permission subsystem, and they are not reachable from any
    public API, so Hubble cannot observe them. A retired platform certificate
    whose capabilities were revoked is therefore indistinguishable here from one
    that retains them, and this method may over-approximate platform trust
    accordingly.

    Args:
      package: A dict representing a package entry from packages.txt.

    Returns:
      True if the package is platform-signed, False otherwise.
    """
    if not isinstance(package, dict):
      return False

    platform_signatures = self.get_platform_signatures()
    if not platform_signatures:
      return False
    return bool(platform_signatures & set(self.get_active_signers(package)))

  def get_platform_signature(self):
    """Returns the active platform signing certificate digest.

    Deprecated: Prefer `is_platform_signed()` for platform matching, or
    `get_platform_signatures()` for the full lineage-aware trust-anchor set when
    the `android` framework signing key has rotated.

    NOTE: For Hubble >= 2.2.0 this is the *currently active* platform signer. For
    legacy (< 2.2.0) output it degrades to `certIds[0]`, which for a rotated key
    is the OLDEST ancestor - matching the historical behaviour of this method.
    """
    if not self._platform_signature:
      for package in self.packages:
        if package["name"] == HubbleParser.PLATFORM_PACKAGE_NAME:
          active_signers = self.get_active_signers(package)
          if active_signers:
            self._platform_signature = active_signers[0]
          break

    return self._platform_signature

  def get_all_packages(self, get_codes_only):
    result = []
    for package in self.packages:
      if not get_codes_only or package["hasCode"]:
        result.append(package["name"])
    return result

  def get_platform_packages(self, get_codes_only):
    result = []
    for package in self.packages:
      if self.is_platform_signed(package):
        if not get_codes_only or package["hasCode"]:
          result.append(package["name"])
    return result

  def print_all_packages(self, print_codes_only):
    for package in self.packages:
      if not print_codes_only or package["hasCode"]:
        print("        \"{}\",".format(package["name"]))

  def print_platform_packages(self, print_codes_only):
    for package in self.packages:
      if self.is_platform_signed(package):
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

  def get_packages_by_signing_mode(self, signing_mode, get_codes_only=False):
    """Returns a list of package names matching a specific signing mode."""
    result = []
    for package in self._get_package_list(allow_preinstalled_fallback=True):
      if self.classify_package_signing(package, self.logger) == signing_mode:
        if not get_codes_only or package.get("hasCode", True):
          result.append(package["name"])
    return result

  def get_key_rotated_packages(self, get_codes_only=False):
    """Returns a list of packages with a v3 signing certificate rotation lineage."""
    return self.get_packages_by_signing_mode(
        HubbleParser.SIGNING_MODE_KEY_ROTATION_LINEAGE,
        get_codes_only=get_codes_only)

  def get_cosigned_packages(self, get_codes_only=False):
    """Returns a list of packages co-signed by multiple active signers."""
    return self.get_packages_by_signing_mode(
        HubbleParser.SIGNING_MODE_MULTIPLE_SIGNERS,
        get_codes_only=get_codes_only)

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
