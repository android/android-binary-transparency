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

"""Performs inclusion proof check against packages in packages.txt or preinstalled_packages.txt."""

import argparse
import json
import logging
import os
import subprocess
import sys
import tempfile
from typing import Optional

OUTPUT_FILENAME = 'packages_with_inclusion_proof_signal.txt'
PREINSTALLED_OUTPUT_FILENAME = (
    'preinstalled_packages_with_inclusion_proof_signal.txt'
)
DEFAULT_PREFETCH_CONCURRENCY = 16
DEFAULT_PREFETCH_TIMEOUT = 600


def prefetch_log_entries(verifier_executable: str,
                         logger: logging.Logger,
                         cache_dir: Optional[str] = None,
                         concurrency: int = DEFAULT_PREFETCH_CONCURRENCY,
                         timeout: int = DEFAULT_PREFETCH_TIMEOUT) -> bool:
  """Pre-fetches and locally caches transparency log entries up to checkpoint.

  Args:
    verifier_executable: path to verifier tool.
    logger: logger instance.
    cache_dir: optional custom root directory for local cache.
    concurrency: number of concurrent worker threads for fetching Tessera tiles.
    timeout: maximum time in seconds to wait for pre-fetching before timing out.

  Returns:
    True if pre-fetching succeeded, False otherwise.
  """
  try:
    cmd = [
        verifier_executable,
        "--log_type=google_1p_apk",
        "--fetch_entries",
        f"--concurrency={concurrency}",
    ]
    if cache_dir:
      cmd.append(f"--cache_dir={cache_dir}")

    logger.info("Pre-fetching transparency log entries (concurrency=%d)...",
                concurrency)
    logger.debug("Running verifier prefetch: %s", " ".join(cmd))
    result = subprocess.run(cmd, check=False, timeout=timeout)
    if result.returncode == 0:
      logger.info("Successfully pre-fetched and cached log entries.")
      return True
    else:
      logger.warning(
          "Pre-fetching log entries exited with code %d. "
          "Falling back to on-demand tile fetching during verification.",
          result.returncode)
      return False
  except subprocess.TimeoutExpired:
    logger.warning(
        "Pre-fetching log entries timed out after %d seconds. "
        "Falling back to on-demand tile fetching during verification.",
        timeout)
    return False
  except FileNotFoundError:
    logger.error("`%s` command not found.", verifier_executable)
    return False
  except Exception as e:
    logger.warning("Error pre-fetching log entries: %s. Continuing...", e)
    return False


def run_verifier(verifier_executable: str, payload_path: str,
                 logger: logging.Logger,
                 cache_dir: Optional[str] = None) -> bool:
  """Runs verifier tool and returns True if inclusion proof is successful."""
  try:
    cmd = [verifier_executable, f"--payload_path={payload_path}",
           "--log_type=google_1p_apk"]
    if cache_dir:
      cmd.append(f"--cache_dir={cache_dir}")
    with open(payload_path, "r") as f_in:
      payload = f_in.read()
      logger.debug("payload content: %s", payload)
    logger.debug("Running verifier: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    logger.debug("Verifier stdout: %s", result.stdout)
    logger.debug("Verifier stderr: %s", result.stderr)
    if ("OK. inclusion check success!" in result.stdout or
        "OK. inclusion check success!" in result.stderr):
      logger.debug("Verifier check passed.")
      return True
    else:
      logger.debug("Verifier check failed.")
      return False
  except FileNotFoundError:
    logger.error("`%s` command not found.", verifier_executable)
    return False
  except Exception as e:
    logger.error("Error running verifier: %s", e)
    return False


def perform_inclusion_proof_check(
    verifier_executable: str,
    packages_file_path: str,
    logger: logging.Logger,
    cache_dir: Optional[str] = None,
    concurrency: int = DEFAULT_PREFETCH_CONCURRENCY,
    timeout: int = DEFAULT_PREFETCH_TIMEOUT,
    prefetch: bool = True,
    preinstalled_only: Optional[bool] = None) -> bool:
  """Reads packages.txt or preinstalled_packages.txt and performs inclusion proof check.

  By default, pre-fetches and locally caches transparency log entries before
  verifying individual package splits. Writes results to file defined in
  OUTPUT_FILENAME in the same directory as packages_file_path.

  Args:
    verifier_executable: path to verifier tool.
    packages_file_path: path to packages.txt or preinstalled_packages.txt.
    logger: logger instance.
    cache_dir: optional custom root directory for local cache.
    concurrency: number of concurrent workers for fetching Tessera entry tiles.
    timeout: maximum time in seconds to wait for pre-fetching before timing out.
    prefetch: whether to pre-fetch log entries before verifying packages.
    preinstalled_only: whether the input file is preinstalled_packages.txt
                       (expects 'preinstalledPackages' key). If None, inferred
                       from packages_file_path basename.

  Returns:
    True if the input file was valid and inclusion proof results were
    successfully written to disk, False otherwise.
  """
  if not os.path.isfile(packages_file_path):
    logger.error("%s not found at %s", os.path.basename(packages_file_path),
                 packages_file_path)
    return False

  logger.info("Performing inclusion proof check...")
  try:
    with open(packages_file_path, "r") as f_in:
      packages_json = json.load(f_in)
  except json.JSONDecodeError as e:
    logger.error("Failed to parse %s: %s", packages_file_path, e)
    return False

  if preinstalled_only is None:
    preinstalled_only = (
        os.path.basename(packages_file_path) == "preinstalled_packages.txt"
    )
  expected_key = "preinstalledPackages" if preinstalled_only else "packages"
  packages_list = packages_json.get(expected_key)
  if not isinstance(packages_list, list):
    logger.error(
        "No valid '%s' list found in %s",
        expected_key,
        packages_file_path)
    return False

  if prefetch and packages_list:
    prefetch_log_entries(
        verifier_executable,
        logger,
        cache_dir=cache_dir,
        concurrency=concurrency,
        timeout=timeout)

  for package in packages_list:
    if "name" not in package or "versionCode" not in package:
      logger.warning("Skipping package due to missing fields: %s",
                     package.get("name", "N/A"))
      continue

    package_name = package["name"]
    version_code = package["versionCode"]
    logger.debug("Processing package: %s version: %s", package_name,
                 version_code)

    if ("splits" not in package or not package["splits"]) and "hash" in package:
      package["splits"] = [{}]
    elif "splits" not in package or not package["splits"]:
      logger.warning("No splits or package hash found for %s, skipping.",
                     package_name)
      continue

    for split in package["splits"]:
      split_hash = ""
      if "hash" in split:
        split_hash = split["hash"]
      elif "hash" in package:
        split_hash = package["hash"]
      else:
        logger.warning("Split in package %s missing 'hash', skipping.",
                       package_name)
        continue

      if "hash" not in split:
        split["hash"] = split_hash

      payload = f"{split_hash}\nSHA256(APK)\n{package_name}\n{version_code}\n"
      temp_payload_path = ""
      try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False,
                                         suffix=".txt") as fp:
          fp.write(payload)
          temp_payload_path = fp.name

        verified = run_verifier(
            verifier_executable,
            temp_payload_path,
            logger,
            cache_dir=cache_dir)
        split["inclusion_proof_verified"] = verified
      finally:
        if temp_payload_path and os.path.exists(temp_payload_path):
          os.remove(temp_payload_path)

  filtered_packages = []
  for p in packages_list:
      if "name" in p and "versionCode" in p and "splits" in p:
          pkg_info = {
              "name": p["name"],
              "versionCode": p["versionCode"],
              "splits": p["splits"]
          }
          if "hash" in p:
              pkg_info["hash"] = p["hash"]
          if "isPreinstalled" in p:
              pkg_info["isPreinstalled"] = p["isPreinstalled"]
          if "isUpdatedSystemApp" in p:
              pkg_info["isUpdatedSystemApp"] = p["isUpdatedSystemApp"]
          if "isApex" in p:
              pkg_info["isApex"] = p["isApex"]
          filtered_packages.append(pkg_info)

  output_json = {
      "source": os.path.basename(packages_file_path),
      "totalPackages": len(filtered_packages),
      "packages": filtered_packages,
  }

  output_filename = (
      PREINSTALLED_OUTPUT_FILENAME if preinstalled_only else OUTPUT_FILENAME
  )
  output_path = os.path.join(os.path.dirname(packages_file_path),
                             output_filename)
  try:
    with open(output_path, "w") as f_out:
      json.dump(output_json, f_out, indent=2)
    logger.info("Inclusion proof results written to %s", output_path)
    return True
  except Exception as e:
    logger.error("Failed to write results to %s: %s", output_path, e)
    return False


def main():
  parser = argparse.ArgumentParser(
      description="Perform inclusion proof check on packages.txt. By default, "
                  "pre-fetches and caches transparency log entries locally "
                  "before verifying individual package splits. Exits 0 when "
                  "results are written to disk (even if individual splits fail "
                  "verification) and exits 1 only on input or execution errors.",
      formatter_class=argparse.ArgumentDefaultsHelpFormatter)
  parser.add_argument("--packages_file", required=True,
                      help="Path to packages.txt file.")
  parser.add_argument("--verifier_path", required=True,
                      help="Path to verifier executable.")
  parser.add_argument("--cache_dir", required=False, default=None,
                      help="Custom root directory for local cache used by "
                           "verifier. If unspecified, defaults to system cache "
                           "directory.")
  parser.add_argument("--cache_prefetch_concurrency", required=False, type=int,
                      default=DEFAULT_PREFETCH_CONCURRENCY,
                      help="Number of concurrent workers for fetching Tessera "
                           "entry tiles when pre-fetching log entries.")
  parser.add_argument("--cache_prefetch_timeout", required=False, type=int,
                      default=DEFAULT_PREFETCH_TIMEOUT,
                      help="Timeout in seconds for pre-fetching transparency "
                           "log entries before falling back to on-demand "
                           "fetching.")
  parser.add_argument("--no_prefetch", required=False, action="store_true",
                      help="If specified, disables pre-fetching and caching of "
                           "transparency log entries before running inclusion "
                           "proof checks.")
  parser.add_argument("-D", "--debug", required=False, action="store_true",
                      help="If specified, debugging mode is turned on.")
  args = parser.parse_args()

  logger = logging.getLogger(__name__)
  if args.debug:
    logger.setLevel(logging.DEBUG)
  else:
    logger.setLevel(logging.INFO)
  s_handler = logging.StreamHandler()
  s_format = logging.Formatter(
      "%(levelname)s:%(filename)s:%(funcName)s(%(lineno)d): %(message)s")
  s_handler.setFormatter(s_format)
  logger.addHandler(s_handler)

  if not perform_inclusion_proof_check(
      args.verifier_path,
      args.packages_file,
      logger,
      cache_dir=args.cache_dir,
      concurrency=args.cache_prefetch_concurrency,
      timeout=args.cache_prefetch_timeout,
      prefetch=not args.no_prefetch):
    sys.exit(1)


if __name__ == "__main__":
  main()
