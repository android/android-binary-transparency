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
import contextlib
import json
import logging
import os
import subprocess
import sys
import tempfile
from typing import Callable, NamedTuple, Optional

import termination

OUTPUT_FILENAME = 'packages_with_inclusion_proof_signal.txt'
PREINSTALLED_OUTPUT_FILENAME = (
    'preinstalled_packages_with_inclusion_proof_signal.txt'
)
# progress(done, total); see perform_inclusion_proof_check().
ProgressCallback = Callable[[int, int], None]
DEFAULT_PREFETCH_CONCURRENCY = 16
DEFAULT_PREFETCH_TIMEOUT = 600
# What a verifier without batch mode prints (Go's flag package, exit code 2)
# when given --payloads_path. Exit code 2 alone is not enough: a Go panic
# exits with 2 too.
_BATCH_UNSUPPORTED_EXIT_CODE = 2
_BATCH_UNSUPPORTED_MESSAGE = "flag provided but not defined: -payloads_path"


class _SplitJob(NamedTuple):
  """One APK split to verify."""
  split: dict  # The split's entry in the package list; receives the result.
  payload: str
  label: str  # Names the package and split in log lines.


def _split_label(package_name: str, split: dict, index: int,
                 split_count: int) -> str:
  """Describes a split for log lines, e.g. 'com.android.chrome [chrome]'."""
  split_name = split.get("name")
  if not split_name:
    split_name = "split {}".format(index) if split_count > 1 else "base"
  return "{} [{}]".format(package_name, split_name)


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
                 cache_dir: Optional[str] = None,
                 label: Optional[str] = None) -> bool:
  """Runs verifier tool and returns True if inclusion proof is successful.

  If interrupted (KeyboardInterrupt, or an exception raised by a signal
  handler), the verifier is killed and the exception propagates.

  Args:
    verifier_executable: path to verifier tool.
    payload_path: path to the payload file to verify.
    logger: logger instance.
    cache_dir: optional custom root directory for local cache.
    label: names the package and split in log lines. Defaults to
           payload_path.

  Returns:
    True if the inclusion proof succeeded; False if it failed or the verifier
    could not be run.
  """
  what = label or payload_path
  try:
    cmd = [verifier_executable, f"--payload_path={payload_path}",
           "--log_type=google_1p_apk"]
    if cache_dir:
      cmd.append(f"--cache_dir={cache_dir}")
    with open(payload_path, "r") as f_in:
      payload = f_in.read()
      logger.debug("%s: payload content: %s", what, payload)
    logger.debug("%s: Running verifier: %s", what, " ".join(cmd))
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True) as process:
      try:
        stdout, stderr = process.communicate()
      except BaseException:
        _kill(process)
        raise
    logger.debug("%s: Verifier stdout: %s", what, stdout)
    logger.debug("%s: Verifier stderr: %s", what, stderr)
    if ("OK. inclusion check success!" in stdout or
        "OK. inclusion check success!" in stderr):
      logger.debug("%s: Verifier check passed.", what)
      return True
    else:
      logger.debug("%s: Verifier check failed.", what)
      return False
  except FileNotFoundError:
    logger.error("%s: `%s` command not found.", what, verifier_executable)
    return False
  except Exception as e:
    logger.error("%s: Error running verifier: %s", what, e)
    return False


def _kill(process: subprocess.Popen) -> None:
  """Kills and reaps a verifier.

  Popen's context manager does not wait for the process after a
  KeyboardInterrupt, so wait here to not leave a zombie behind.
  """
  process.kill()
  process.wait()


def _verify_split(job: _SplitJob, verifier_executable: str,
                  logger: logging.Logger, cache_dir: Optional[str]) -> bool:
  """Verifies one split with a verifier run of its own."""
  temp_payload_path = ""
  try:
    with tempfile.NamedTemporaryFile(mode="w", delete=False,
                                     suffix=".txt") as fp:
      fp.write(job.payload)
      temp_payload_path = fp.name

    return run_verifier(
        verifier_executable,
        temp_payload_path,
        logger,
        cache_dir=cache_dir,
        label=job.label)
  finally:
    if temp_payload_path and os.path.exists(temp_payload_path):
      os.remove(temp_payload_path)


def _write_payloads_file(jobs: list) -> str:
  """Writes the jobs' payloads to a new JSON Lines file; returns its path."""
  fd, path = tempfile.mkstemp(suffix=".jsonl")
  try:
    with os.fdopen(fd, "w") as fp:
      for job in jobs:
        fp.write(json.dumps({"payload": job.payload}) + "\n")
  except BaseException:
    os.remove(path)
    raise
  return path


def _verify_splits_batch(jobs: list, verifier_executable: str,
                         logger: logging.Logger, cache_dir: Optional[str],
                         report: Callable[[_SplitJob, bool], None]) -> list:
  """Verifies jobs with a single verifier run in batch mode (--payloads_path).

  One run fetches each log's checkpoint and searches its entries once for
  all splits, instead of once per split. Calls report(job, verified) as each
  result arrives. If interrupted, the verifier is killed and the exception
  propagates.

  Returns:
    The jobs that got no result, in their original order: all of them if the
    verifier does not support batch mode or could not be run, and the rest
    if it stopped early or printed malformed results. Empty if the verifier
    executable is missing or not executable: then every job is reported as
    not verified, since running it per split would fail the same way.
  """
  reported = set()
  returncode = None
  with contextlib.ExitStack() as cleanup:
    try:
      payloads_path = _write_payloads_file(jobs)
      cleanup.callback(os.remove, payloads_path)
      # stderr (the verifier's log) goes to a file, so that it cannot fill a
      # pipe and block the verifier while stdout is read here.
      stderr_file = cleanup.enter_context(tempfile.TemporaryFile(mode="w+"))
    except OSError as e:
      logger.warning("Could not prepare batch verification: %s", e)
      return list(jobs)

    cmd = [verifier_executable, f"--payloads_path={payloads_path}",
           "--log_type=google_1p_apk"]
    if cache_dir:
      cmd.append(f"--cache_dir={cache_dir}")
    logger.debug("Running verifier in batch mode: %s", " ".join(cmd))
    try:
      process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                 stderr=stderr_file, text=True)
    except (FileNotFoundError, PermissionError) as e:
      # E.g. a wrong --verifier_path. Running it once per split would fail
      # the same way for each, so give every split its result now.
      logger.error("Cannot run verifier `%s`: %s. Marking %d split(s) as not "
                   "verified.", verifier_executable, e, len(jobs))
      for job in jobs:
        report(job, False)
      return []
    except OSError as e:
      logger.warning("Could not run verifier in batch mode: %s", e)
      return list(jobs)

    with process:
      try:
        # Results are read as they arrive. In the main thread, signals
        # interrupt this blocking read.
        for line in process.stdout:
          if not line.strip():
            continue
          try:
            result = json.loads(line)
            index, verified = result["index"], result["verified"]
          except (ValueError, KeyError, TypeError):
            logger.warning("Ignoring malformed verifier result: %r", line)
            continue
          if (type(index) is not int or not 0 <= index < len(jobs) or
              index in reported or type(verified) is not bool):
            logger.warning("Ignoring unexpected verifier result: %r", line)
            continue
          reported.add(index)
          job = jobs[index]
          if result.get("error"):
            logger.warning("%s: Inclusion proof failed: %s", job.label,
                           result["error"])
          logger.debug("%s: Verifier check %s.", job.label,
                       "passed" if verified else "failed")
          report(job, verified)
        returncode = process.wait()
      except BaseException:
        # E.g. Ctrl-C: do not leave the verifier behind.
        _kill(process)
        raise
    stderr_file.seek(0)
    stderr = stderr_file.read()

  logger.debug("Batch verifier stderr: %s", stderr)
  remaining = [job for i, job in enumerate(jobs) if i not in reported]
  if (returncode == _BATCH_UNSUPPORTED_EXIT_CODE and not reported and
      _BATCH_UNSUPPORTED_MESSAGE in stderr):
    # An older verifier, which rejects the unknown --payloads_path flag.
    logger.warning("Verifier does not support batch mode; verifying %d "
                   "split(s) one at a time, which is slow. Rebuild the "
                   "verifier for faster checks.", len(jobs))
  elif remaining and returncode is not None:
    logger.warning("Batch verifier exited with code %d after %d of %d "
                   "results; verifying the remaining %d split(s) one at a "
                   "time.", returncode, len(reported), len(jobs),
                   len(remaining))
  return remaining


def _verify_splits(jobs: list, verifier_executable: str,
                   logger: logging.Logger, cache_dir: Optional[str],
                   progress: Optional[ProgressCallback] = None) -> None:
  """Verifies jobs, preferably with one batch-mode verifier run.

  Splits that the batch run gives no result for (e.g. with a verifier that
  does not support batch mode) are then verified one at a time, with a
  verifier run each.

  Stores each result as job.split["inclusion_proof_verified"].

  If interrupted (KeyboardInterrupt, or an exception raised by a SIGTERM
  handler), the running verifier is killed, no more are started, and the
  exception propagates.
  """
  total = len(jobs)
  done_count = 0

  def report(job: _SplitJob, verified: bool) -> None:
    nonlocal done_count
    job.split["inclusion_proof_verified"] = verified
    done_count += 1
    if progress is not None:
      progress(done_count, total)

  try:
    if progress is not None:
      progress(0, total)
    remaining = jobs
    if jobs:
      remaining = _verify_splits_batch(jobs, verifier_executable, logger,
                                       cache_dir, report)
    for job in remaining:
      report(job, _verify_split(job, verifier_executable, logger, cache_dir))
  except (KeyboardInterrupt, termination.Terminated):
    logger.warning("Inclusion proof check interrupted after %d of %d "
                   "split(s).", done_count, total)
    raise


def perform_inclusion_proof_check(
    verifier_executable: str,
    packages_file_path: str,
    logger: logging.Logger,
    cache_dir: Optional[str] = None,
    concurrency: int = DEFAULT_PREFETCH_CONCURRENCY,
    timeout: int = DEFAULT_PREFETCH_TIMEOUT,
    prefetch: bool = True,
    preinstalled_only: Optional[bool] = None,
    progress: Optional[ProgressCallback] = None) -> bool:
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
    progress: optional callback, called in the calling thread as
              progress(done, total): once with done=0 when verification
              starts (after the input was read and pre-fetching, if any,
              is over), then after each split is verified. total is the
              number of splits to verify; skipped splits are not counted.
              Not called if the input file cannot be read. Calls are not
              throttled.

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

  # Collect the splits to verify first, then verify them (in one batch run
  # if possible). Each job refers to its split's own dict, so the output
  # keeps the input's package and split order.
  jobs = []
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

    splits = package["splits"]
    for index, split in enumerate(splits):
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
      jobs.append(_SplitJob(
          split=split,
          payload=payload,
          label=_split_label(package_name, split, index, len(splits))))

  if jobs:
    logger.info("Verifying %d APK split(s) in one batch verifier run...",
                len(jobs))
  _verify_splits(jobs, verifier_executable, logger, cache_dir,
                 progress=progress)

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

  # Turn SIGTERM into an exception so that running verifiers are killed
  # instead of being left behind, then die by SIGTERM as before.
  terminated = False
  with termination.sigterm_raises():
    try:
      ok = perform_inclusion_proof_check(
          args.verifier_path,
          args.packages_file,
          logger,
          cache_dir=args.cache_dir,
          concurrency=args.cache_prefetch_concurrency,
          timeout=args.cache_prefetch_timeout,
          prefetch=not args.no_prefetch)
    except termination.Terminated:
      terminated = True
  if terminated:
    termination.die_by_sigterm(logger)
  if not ok:
    sys.exit(1)


if __name__ == "__main__":
  main()
