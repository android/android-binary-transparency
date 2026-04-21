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

"""Performs inclusion proof check against packages in packages.txt."""

import argparse
import json
import logging
import os
import subprocess
import tempfile

OUTPUT_FILENAME = 'packages_with_inclusion_proof_signal.txt'

def run_verifier(verifier_executable: str, payload_path: str,
                 logger: logging.Logger) -> bool:
  """Runs verifier tool and returns True if inclusion proof is successful."""
  try:
    cmd = [verifier_executable, f"--payload_path={payload_path}",
           "--log_type=google_1p_apk"]
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


def perform_inclusion_proof_check(verifier_executable: str,
                                  packages_file_path: str,
                                  logger: logging.Logger):
  """Reads packages.txt and performs inclusion proof check for each APK split.

  It writes results to file which name defined in OUTPUT_FILENAME in same dir.

  Args:
    verifier_executable: path to verifier tool.
    packages_file_path: path to packages.txt.
    logger: logger instance.
  """
  if not os.path.isfile(packages_file_path):
    logger.error("packages.txt not found at %s", packages_file_path)
    return

  logger.info("Performing inclusion proof check...")
  try:
    with open(packages_file_path, "r") as f_in:
      packages_json = json.load(f_in)
  except json.JSONDecodeError as e:
    logger.error("Failed to parse %s: %s", packages_file_path, e)
    return

  if "packages" not in packages_json:
    logger.error("No 'packages' key in %s", packages_file_path)
    return

  for package in packages_json["packages"]:
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

        verified = run_verifier(verifier_executable, temp_payload_path, logger)
        split["inclusion_proof_verified"] = verified
      finally:
        if temp_payload_path and os.path.exists(temp_payload_path):
          os.remove(temp_payload_path)

  filtered_packages = []
  for p in packages_json.get("packages", []):
      if "name" in p and "versionCode" in p and "splits" in p:
          pkg_info = {
              "name": p["name"],
              "versionCode": p["versionCode"],
              "splits": p["splits"]
          }
          if "hash" in p:
              pkg_info["hash"] = p["hash"]
          filtered_packages.append(pkg_info)

  output_json = {
      "packages": filtered_packages
  }

  output_path = os.path.join(os.path.dirname(packages_file_path),
                             OUTPUT_FILENAME)
  try:
    with open(output_path, "w") as f_out:
      json.dump(output_json, f_out, indent=2)
    logger.info("Inclusion proof results written to %s", output_path)
  except Exception as e:
    logger.error("Failed to write results to %s: %s", output_path, e)


def main():
  parser = argparse.ArgumentParser(
      description="Perform inclusion proof check on packages.txt.",
      formatter_class=argparse.ArgumentDefaultsHelpFormatter)
  parser.add_argument("--packages_file", required=True,
                      help="Path to packages.txt file.")
  parser.add_argument("--verifier_path", required=True,
                      help="Path to verifier executable.")
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

  perform_inclusion_proof_check(args.verifier_path, args.packages_file, logger)


if __name__ == "__main__":
  main()
