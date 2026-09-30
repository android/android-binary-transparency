#!/usr/bin/python3
# Copyright 2026 Uraniborg authors.
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

"""Worker thread that automates various steps of observation process.

This is a script that automates the installation and launching of Hubble. It
also detects execution state and result and automates the 'downloading' of
Hubble data back to host.
"""
import argparse
import contextlib
import dataclasses
import datetime
import io   # to convert regular buffer to in-memory bytes buffer for tarfileobj
import json
import logging
import os
import shutil  # to help move files
import signal
import sys
import tarfile  # to untar decompressed adb backup file
import tempfile
import time
from typing import Optional, TextIO  # runtime support for type hints.
import zlib  # to decompress adb backup

import inclusion_proof_check
import syscall_wrapper
import termination

AdbWrapper = syscall_wrapper.AdbWrapper
SyscallWrapper = syscall_wrapper.SyscallWrapper

HUBBLE_PACKAGE_NAME = "com.uraniborg.hubble"
HUBBLE_LOGCAT_TAG = "HUBBLE"
HUBBLE_RESULT_STRING = "Results are available at:"


def parse_arguments() -> argparse.Namespace:
  """Parses cmdline arguments.

  Returns:
    An object containing information about arguments that are passed within
    this namespace.
  """
  parser = argparse.ArgumentParser(
      description="A script that automates the installation, launch, and"
                  "result-pulling from Hubble. The user should only need to"
                  "supply the location of Hubble APK, and this script should"
                  "take care of the rest. In the case that more than 1 Android"
                  "devices is plugged in, user specification will be required.",
      formatter_class=argparse.ArgumentDefaultsHelpFormatter)

  parser.add_argument("-H", "--hubble", required=False,
                      default=None,
                      help="The path to where Hubble APK is on your "
                      "system/host. If not specified, Hubble will be rebuilt.")
  parser.add_argument("-o", "--output", required=False,
                      default=os.path.join(os.getcwd(), "results"),
                      help="Specifies the output directory where the "
                      "\"results\" directory can be found.")
  parser.add_argument("-D", "--debug", required=False, action="count",
                      help="If specified, debugging mode is turned on.")
  parser.add_argument("-s", "--serial", required=False, action="append",
                      default=None, metavar="SERIAL",
                      help="Serial number of a connected device to observe "
                           "(as listed by `adb devices`). May be repeated to "
                           "observe several devices, which are processed in "
                           "the order given. If omitted, every connected "
                           "device is observed. A requested serial that is "
                           "not connected is reported as FAILED.")
  parser.add_argument("--events", required=False, default=None,
                      metavar="PATH",
                      help="If specified, writes machine-readable progress "
                           "events as JSON Lines (one JSON object per line) "
                           "to PATH, overwriting it. Use \"-\" to write events "
                           "to stdout; everything else the script would print "
                           "to stdout is then sent to stderr, so stdout "
                           "carries only events. See "
                           "docs/automate_observation.md for the schema.")
  parser.add_argument("--pull-all-apks", required=False,
                      action="count",
                      help="If specified, the script will attempt to download "
                           "APKs from the device. The resulting APKs will be "
                           "stored in an \"apks\" directory within the "
                           "specific numbered results directory.")
  parser.add_argument("--pull-preinstalled-apks-only", required=False,
                      action="store_true",
                      help="If specified, only pre-installed packages (from "
                           "preinstalled_packages.txt) will be extracted "
                           "from the device.")
  parser.add_argument("--perform_inclusion_proof_check", required=False,
                      action="store_true",
                      help="If specified, after pulling results, perform "
                           "inclusion proof check for each package APK split "
                           "and write results to "
                           "packages_with_inclusion_proof_signal.txt (or "
                           "preinstalled_packages_with_inclusion_proof_signal.txt "
                           "when --check_preinstalled_only is set). By "
                           "default, transparency log entries are pre-fetched "
                           "and cached locally beforehand.")
  parser.add_argument("--check_preinstalled_only", required=False,
                      action="store_true",
                      help="If specified, performs inclusion proof checks "
                           "against preinstalled_packages.txt instead of "
                           "packages.txt and writes results to "
                           "preinstalled_packages_with_inclusion_proof_signal.txt.")
  parser.add_argument("--verifier_path", required=False,
                      help="Path to verifier executable, used if "
                           "--perform_inclusion_proof_check is specified.")
  parser.add_argument("--cache_dir", required=False, default=None,
                      help="Custom root directory for local cache used by "
                           "verifier during inclusion proof checks. If "
                           "unspecified, defaults to system cache directory.")
  parser.add_argument("--cache_prefetch_concurrency", required=False, type=int,
                      default=inclusion_proof_check.DEFAULT_PREFETCH_CONCURRENCY,
                      help="Number of concurrent workers for fetching Tessera "
                           "entry tiles when pre-fetching log entries during "
                           "inclusion proof checks.")
  parser.add_argument("--cache_prefetch_timeout", required=False, type=int,
                      default=inclusion_proof_check.DEFAULT_PREFETCH_TIMEOUT,
                      help="Timeout in seconds for pre-fetching transparency "
                           "log entries before falling back to on-demand "
                           "fetching.")
  parser.add_argument("--no_prefetch", required=False, action="store_true",
                      help="If specified, disables pre-fetching and caching of "
                           "transparency log entries before running inclusion "
                           "proof checks (pre-fetching is enabled by default "
                           "when --perform_inclusion_proof_check is specified).")
  args = parser.parse_args()

  if args.perform_inclusion_proof_check and args.verifier_path is None:
    parser.error("--verifier_path is required when --perform_inclusion_proof_check is specified.")
  return args


def validate_argument_combinations(args: argparse.Namespace) -> list[str]:
  """Finds flags that are ignored because of how they are combined.

  These combinations are not errors, so that existing invocations keep
  working; run() logs each returned message as a warning. Combinations that
  cannot work at all are rejected by parse_arguments() instead.

  Args:
    args: Parsed arguments from parse_arguments().

  Returns:
    One human-readable warning per ignored flag or conflict, in a stable
    order. Empty if nothing is ignored.
  """
  warnings = []
  # Integer flags always have a value, so only a non-default one counts as
  # given. Only prefetch_log_entries() reads them.
  prefetch_tuning = [
      ("--cache_prefetch_concurrency",
       args.cache_prefetch_concurrency !=
       inclusion_proof_check.DEFAULT_PREFETCH_CONCURRENCY),
      ("--cache_prefetch_timeout",
       args.cache_prefetch_timeout !=
       inclusion_proof_check.DEFAULT_PREFETCH_TIMEOUT),
  ]
  if not args.perform_inclusion_proof_check:
    ignored = [
        ("--check_preinstalled_only", args.check_preinstalled_only),
        ("--verifier_path", args.verifier_path is not None),
        ("--no_prefetch", args.no_prefetch),
        ("--cache_dir", args.cache_dir is not None),
    ] + prefetch_tuning
    for flag, given in ignored:
      if given:
        warnings.append("{} has no effect without "
                        "--perform_inclusion_proof_check.".format(flag))
  elif args.no_prefetch:
    # Pre-fetching is skipped, so its tuning flags are unused. --cache_dir is
    # not: verification itself still uses the cache.
    for flag, given in prefetch_tuning:
      if given:
        warnings.append("{} has no effect with --no_prefetch.".format(flag))
  if args.pull_all_apks is not None and args.pull_preinstalled_apks_only:
    warnings.append("--pull-all-apks and --pull-preinstalled-apks-only were "
                    "both given; only pre-installed APKs will be pulled.")
  return warnings


def set_up_logging(args: argparse.Namespace) -> logging.Logger:
  """Sets up various logging parameters.

  Args:
    args: Parsed arguments from calling argparse.ArgumentParser()

  Returns:
    A logger object suitable for usage.
  """
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
  return logger


# --- Machine-readable progress events (--events) ------------------------------
#
# The schema is documented in docs/automate_observation.md and is a stable
# contract: fields and event types may be added without bumping
# EVENTS_SCHEMA_VERSION, but never removed or changed in meaning.

EVENTS_SCHEMA_VERSION = 1

# step_progress events are written at most this often (plus the first and
# the final one of each step).
STEP_PROGRESS_INTERVAL_SECONDS = 2.0

# Per-device outcomes. These are the same four outcomes the final log summary
# distinguishes.
STATUS_SUCCESS = "success"
STATUS_PARTIAL_CHECK_INCOMPLETE = "partial_check_incomplete"
STATUS_PARTIAL_ERROR = "partial_error"
STATUS_FAILED = "failed"

# Error reasons. `error` fields in run_finished and device_finished are
# {reason, message}: reason is one of these stable codes, message is free text.
#
# run_finished.error, when the run stops before processing any device:
REASON_UNSUPPORTED_PLATFORM = "unsupported_platform"
REASON_ANDROID_SDK_NOT_FOUND = "android_sdk_not_found"
REASON_HUBBLE_BUILD_FAILED = "hubble_build_failed"
REASON_INVALID_HUBBLE_APK = "invalid_hubble_apk"
REASON_ADB_NOT_FOUND = "adb_not_found"
REASON_ADB_SERVER_FAILED = "adb_server_failed"
REASON_ADB_DEVICES_FAILED = "adb_devices_failed"
REASON_NO_DEVICES = "no_devices"
# device_finished.error only:
REASON_NOT_CONNECTED = "not_connected"
REASON_UNAUTHORIZED = "unauthorized"
REASON_UNINSTALL_FAILED = "uninstall_failed"
REASON_INSTALL_FAILED = "install_failed"
REASON_LAUNCH_FAILED = "launch_failed"
REASON_NO_RESULTS = "no_results"
REASON_EXTRACT_FAILED = "extract_failed"
REASON_INCLUSION_PROOF_CHECK_INCOMPLETE = "inclusion_proof_check_incomplete"
REASON_STDIN_CLOSED = "stdin_closed"
# Both run_finished.error and device_finished.error:
REASON_UNEXPECTED_ERROR = "unexpected_error"
REASON_INTERRUPTED = "interrupted"
REASON_TERMINATED = "terminated"

# Kinds of manual intervention reported by prompt / prompt_resolved events.
PROMPT_XIAOMI_MANUAL_INSTALL = "xiaomi_manual_install"
PROMPT_ADB_BACKUP_CONFIRM = "adb_backup_confirm"

# How a prompt ended, reported by prompt_resolved.outcome. An exception during
# the wait maps to REASON_INTERRUPTED, REASON_TERMINATED or
# REASON_UNEXPECTED_ERROR.
PROMPT_OUTCOME_DONE = "done"
PROMPT_OUTCOME_FAILED = "failed"
PROMPT_OUTCOME_STDIN_CLOSED = REASON_STDIN_CLOSED


def _interruption_error(e: BaseException) -> dict:
  """Describes an exception that is not an Exception, for device errors."""
  if isinstance(e, KeyboardInterrupt):
    return _error(REASON_INTERRUPTED, "Interrupted.")
  if isinstance(e, termination.Terminated):
    return _error(REASON_TERMINATED, "Terminated.")
  return _error(REASON_UNEXPECTED_ERROR,
                "{}: {}".format(type(e).__name__, e))


def open_event_stream(path: str) -> TextIO:
  """Opens the destination for --events.

  For "-", events go to the process's original stdout. To guarantee that
  stdout then carries nothing but events, file descriptor 1 is redirected to
  stderr afterwards, so anything else written to stdout -- by this script,
  input() prompts, or child processes that inherit stdout -- lands on stderr.

  Args:
    path: A file path, or "-" for stdout.

  Returns:
    A writable text stream.

  Raises:
    OSError: if the destination cannot be opened.
  """
  if path == "-":
    sys.stdout.flush()
    events_fd = os.dup(sys.stdout.fileno())
    os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
    return os.fdopen(events_fd, "w", encoding="utf-8")
  return open(path, "w", encoding="utf-8")


class _Step:
  """Handle yielded by EventEmitter.step() to mark a step as failed."""

  def __init__(self):
    self.failed = False
    self.message = None

  def fail(self, message: str) -> str:
    """Marks the step failed and returns message, for convenient reuse."""
    self.failed = True
    self.message = message
    return message


class _Prompt:
  """Handle yielded by EventEmitter.prompt() to record how the wait ended."""

  def __init__(self):
    self.outcome = PROMPT_OUTCOME_DONE


class EventEmitter:
  """Writes progress events as JSON Lines.

  Without a stream every method is a no-op, so callers never need to check
  whether --events was given. Writing is best-effort: if the destination
  breaks (e.g. the reading process went away), a warning is logged once and
  the run carries on without events.
  """

  def __init__(self, stream: Optional[TextIO] = None,
               logger: Optional[logging.Logger] = None,
               clock=None, monotonic=None):
    self._stream = stream
    self._logger = logger
    self._clock = clock or (
        lambda: datetime.datetime.now(datetime.timezone.utc))
    # Used only to throttle step_progress events.
    self._monotonic = monotonic or time.monotonic
    self._run_finished = False
    # serial -> {status, results_dir?}, in device_finished order.
    self._finished_devices = {}

  @property
  def enabled(self) -> bool:
    return self._stream is not None

  def emit(self, event_type: str, **fields):
    """Writes one event. Fields whose value is None are omitted."""
    if self._stream is None:
      return
    timestamp = self._clock().isoformat(timespec="milliseconds")
    event = {"v": EVENTS_SCHEMA_VERSION,
             "ts": timestamp.replace("+00:00", "Z"),
             "type": event_type}
    event.update({k: v for k, v in fields.items() if v is not None})
    try:
      self._stream.write(json.dumps(event, default=str) + "\n")
      self._stream.flush()
    except (OSError, ValueError) as e:
      # ValueError: write to a closed file.
      if self._logger:
        self._logger.warning("Failed to write --events output (%s); "
                             "continuing without events.", e)
      self._stream = None

  def device_finished(self, device: str, status: str,
                      results_dir: Optional[str] = None,
                      error: Optional[dict] = None):
    """Emits device_finished and remembers the outcome for finish_run()."""
    entry = {"status": status}
    if results_dir is not None:
      entry["results_dir"] = results_dir
    self._finished_devices[device] = entry
    self.emit("device_finished", device=device, status=status,
              results_dir=results_dir, error=error)

  def progress_reporter(
      self, step: str, device: Optional[str] = None,
      interval: float = STEP_PROGRESS_INTERVAL_SECONDS):
    """Returns a progress(done, total) callback emitting step_progress.

    Meant to be called often (e.g. once per item); events are throttled:
    the first call is always reported, and so is the one where done reaches
    total, but in between at most one event is written per `interval`
    seconds. A call repeating the last reported `done` is never reported.
    """
    last = {"done": None, "at": None}

    def report(done: int, total: int) -> None:
      if self._stream is None or done == last["done"]:
        return
      now = self._monotonic()
      if (last["at"] is not None and done != total and
          now - last["at"] < interval):
        return
      last["done"], last["at"] = done, now
      self.emit("step_progress", step=step, device=device, done=done,
                total=total)

    return report

  @contextlib.contextmanager
  def step(self, name: str, device: Optional[str] = None):
    """Brackets a phase with step started/finished/failed events.

    The step is reported as failed if the body raises (the exception is
    re-raised) or calls fail() on the yielded handle; otherwise as finished.
    """
    handle = _Step()
    start = time.monotonic()
    self.emit("step", step=name, state="started", device=device)
    try:
      yield handle
    except BaseException as e:
      self.emit("step", step=name, state="failed", device=device,
                duration_ms=int((time.monotonic() - start) * 1000),
                message="{}: {}".format(type(e).__name__, e))
      raise
    self.emit("step", step=name,
              state="failed" if handle.failed else "finished",
              device=device,
              duration_ms=int((time.monotonic() - start) * 1000),
              message=handle.message)

  @contextlib.contextmanager
  def prompt(self, device: Optional[str], kind: str, message: str,
             expects_input: bool):
    """Brackets a wait for manual intervention with prompt/prompt_resolved.

    prompt_resolved is emitted however the body exits, including by an
    exception, so every prompt is closed. Its outcome is "done" unless the
    body sets another PROMPT_OUTCOME_* on the yielded handle, or raises (then
    it is the matching error reason, e.g. "interrupted"). expects_input tells
    the reader whether the script is blocked on stdin (write a newline to
    continue) or on an action on the device.
    """
    handle = _Prompt()
    self.emit("prompt", device=device, kind=kind, message=message,
              expects_input=expects_input)
    try:
      yield handle
    except BaseException as e:
      handle.outcome = _interruption_error(e)["reason"]
      raise
    finally:
      self.emit("prompt_resolved", device=device, kind=kind,
                outcome=handle.outcome)

  def finish_run(self, exit_code: int, summary: Optional[dict] = None,
                 error: Optional[dict] = None):
    """Emits run_finished. Only the first call has any effect.

    If summary is None, it defaults to the devices reported through
    device_finished() so far, so a run that is cut short still reports the
    devices that did finish.
    """
    if self._run_finished:
      return
    self._run_finished = True
    self.emit("run_finished",
              exit_code=exit_code,
              ok=(exit_code == 0 and error is None),
              summary=(summary if summary is not None
                       else dict(self._finished_devices)),
              error=error)

  def close(self):
    if self._stream is not None:
      try:
        self._stream.close()
      except OSError:
        pass
      self._stream = None


def _error(reason: str, message: str) -> dict:
  """Builds an `error` field: a stable REASON_* code plus free text."""
  return {"reason": reason, "message": message}


def _device_to_event(device) -> dict:
  """Describes a DeviceInfo for the devices event."""
  info = {"serial": device.serial_number,
          "unauthorized": bool(device.unauthorized)}
  for key, attr in (("model", "model_name"), ("product", "product_name"),
                    ("device", "device_name")):
    value = getattr(device, attr, None)
    if isinstance(value, str) and value:
      info[key] = value
  return info


def classify_device(collected: bool, collection_error: bool,
                    check_incomplete: bool) -> str:
  """Maps what happened on one device to one of the STATUS_* values."""
  if not collected:
    return STATUS_FAILED
  if collection_error:
    return STATUS_PARTIAL_ERROR
  if check_incomplete:
    return STATUS_PARTIAL_CHECK_INCOMPLETE
  return STATUS_SUCCESS


@dataclasses.dataclass
class DeviceResult:
  """The outcome of observing one device, as reported by device_finished."""
  status: str
  results_dir: Optional[str] = None
  error: Optional[dict] = None


@dataclasses.dataclass
class RunState:
  """State carried from one device to the next within a run."""
  # Log entries only need pre-fetching once per run.
  prefetched: bool = False


@dataclasses.dataclass
class _DeviceProgress:
  """What process_device() has learned about one device so far."""
  results_dir: Optional[str] = None  # set once results are fully collected
  error: Optional[dict] = None
  collection_error: bool = False
  check_incomplete: bool = False

  def result(self) -> DeviceResult:
    return DeviceResult(
        status=classify_device(self.results_dir is not None,
                               self.collection_error, self.check_incomplete),
        results_dir=self.results_dir,
        error=self.error)


def supported_platform(logger: logging.Logger) -> bool:
  """Checks if this script is running on supported platform.

  Args:
    logger: A valid logger instance to log debug/error messages.

  Returns:
    True if this platform is supported.
  """
  # TODO(billy): Look into supporting Windows in the near future.
  logger.debug("Current platform: {}".format(sys.platform))
  if not (sys.platform == "linux" or sys.platform == "darwin"):
    logger.error("Sorry, your OS is currently unsupported for this script.")
    return False

  if not (sys.version_info.major == 3 and sys.version_info.minor >= 5):
    logger.error("This script requires Python 3.5 or higher!")
    logger.error("You are using Python {}.{}.".format(sys.version_info.major,
                                                      sys.version_info.minor))
    return False
  return True


def verify_hubble(args: argparse.Namespace, logger: logging.Logger) -> bool:
  # First, resolve the path if it's a symlink
  args.hubble = os.path.realpath(args.hubble)
  logger.debug("Hubble's realpath: %s", args.hubble)

  if not args.hubble.endswith(".apk"):
    logger.error("Hubble APK to be installed must have the .apk extension.")
    return False

  return True


def adb_installed(logger: logging.Logger) -> bool:
  cmd = ["which", "adb"]
  sw = SyscallWrapper(logger)
  sw.call_returnable_command(cmd)
  if sw.return_code == 0:
    logger.debug("ADB was found on system, installed at: %s", sw.result_final)
    return True

  logger.debug("ADB was NOT found on system!")
  return False


def select_target_devices(connected_devices: list,
                          requested_serials: Optional[list[str]],
                          logger: logging.Logger) -> tuple[list, list[str]]:
  """Narrows connected devices down to the ones requested via --serial.

  Args:
    connected_devices: DeviceInfo-like objects as returned by
                       AdbWrapper.devices().
    requested_serials: Serial numbers passed via --serial, or None if the flag
                       was not used. Duplicates are ignored.
    logger: A logger object to log debug or error messages.

  Returns:
    A tuple (target_devices, missing_serials). When requested_serials is None,
    target_devices is connected_devices unchanged and missing_serials is empty.
    Otherwise target_devices holds the connected devices matching the request,
    in the order the serials were requested, and missing_serials holds the
    requested serials that are not connected, also in request order.
  """
  if requested_serials is None:
    return list(connected_devices), []

  by_serial = {d.serial_number: d for d in connected_devices}
  target_devices = []
  missing_serials = []
  seen = set()
  for serial in requested_serials:
    if serial in seen:
      logger.debug("Ignoring duplicate --serial %s", serial)
      continue
    seen.add(serial)
    if serial in by_serial:
      target_devices.append(by_serial[serial])
    else:
      logger.error("Requested device with serial number %s is not connected.",
                   serial)
      missing_serials.append(serial)
  return target_devices, missing_serials


def clear_logcat(adb_wrapper):
  adb_wrapper.logcat_clear()


def is_hubble_installed(adb_wrapper: syscall_wrapper.AdbWrapper,
                        logger: logging.Logger) -> bool:
  """Checks if Hubble is already installed on device.

  Args:
    adb_wrapper: An AdbWrapper object that is used to issue ADB commands.
    logger: A logger object to log debug or error messages.

  Returns:
    A boolean indicating whether or not Hubble was installed on the connected
    device.

  Raises:
    RuntimeError: if something went wrong within the ADB call. This means the
                  status of Hubble installation can't be determined, therefore
                  is not suitable as a return value.
  """
  check_installation_cmd = ["pm", "list", "packages"]
  if not adb_wrapper.shell(check_installation_cmd):
    raise RuntimeError("Querying for Hubble installation failed.")

  for package_name in adb_wrapper.get_result():
    if HUBBLE_PACKAGE_NAME in package_name:
      logger.debug("Hubble was previously installed")
      return True
  logger.debug("Hubble was not found installed.")
  return False


def is_xiaomi_phone(adb_wrapper: syscall_wrapper.AdbWrapper,
                    logger: logging.Logger) -> bool:
  """Checks if the connected device is a Xiami device.

  We do this by checking various strings within the device property for any
  signs of "xiaomi"

  Args:
    adb_wrapper: An AdbWrapper object that is used to issue ADB commands.
    logger: A logger object to log debug or error messages.

  Returns:
    A boolean indicating whether or not the connected device is a Xiaomi device.
  """
  getprop_cmd = ["getprop"]
  if not adb_wrapper.shell(getprop_cmd):
    return False

  for line in adb_wrapper.get_result():
    # Split once on ": "; continuation lines of multi-line properties lack this
    # delimiter and are intentionally skipped.
    components = line.split(": ", 1)
    if len(components) < 2:
      continue
    if "oem" in components[0].strip().lower():
      logger.debug("Found oem in field: %s", components[0])
      if "xiaomi" in components[1].strip().lower():
        logger.debug("Found xiaomi in value: %s", components[1])
        return True
    elif "brand" in components[0].strip().lower():
      logger.debug("Found brand in field: %s", components[0])
      if "xiaomi" in components[1].strip().lower():
        logger.debug("Found xiaomi in value %s", components[1])
        return True
  return False


def launch_xiaomi_file_explorer(
    adb_wrapper: syscall_wrapper.AdbWrapper) -> bool:
  return adb_wrapper.am_start(
      "com.mi.android.globalFileexplorer",
      "com.android.fileexplorer.FileExplorerTabActivity")


def wait_for_xiaomi_manual_install(adb_wrapper: syscall_wrapper.AdbWrapper,
                                   serial: str,
                                   logger: logging.Logger,
                                   events: EventEmitter) -> bool:
  """Waits, via stdin, for the user to install Hubble by hand on a Xiaomi phone.

  The user is asked to press Enter after installing; this repeats until Hubble
  is installed. With --events, the wait is reported as a prompt event so that
  a parent process can ask its user and then write a newline to stdin.

  Args:
    adb_wrapper: An AdbWrapper for the target device.
    serial: The target device's serial number, for events.
    logger: A logger object to log messages.
    events: The EventEmitter for the run.

  Returns:
    True once Hubble is installed; False if stdin was closed first (e.g. the
    parent process cancelled the run, or stdin is /dev/null).
  """
  if is_hubble_installed(adb_wrapper, logger):
    return True
  with events.prompt(serial, PROMPT_XIAOMI_MANUAL_INSTALL,
                     "Install Hubble manually from the \"Downloads\" folder "
                     "in the \"Files Manager\" app on the device, then press "
                     "Enter.",
                     expects_input=True) as prompt:
    while True:
      logger.warning("Please manually install Hubble by launching the "
                     "\"Files Manager\" app (it may have been launched "
                     "for you) and navigate to the \"Downloads\" folder.")
      try:
        input("Press [ENTER] when you are done.")
      except EOFError:
        logger.error("Standard input was closed while waiting for Hubble to "
                     "be installed manually on device %s.", serial)
        prompt.outcome = PROMPT_OUTCOME_STDIN_CLOSED
        return False
      if is_hubble_installed(adb_wrapper, logger):
        return True


def adb_push_hubble(adb_wrapper: syscall_wrapper.AdbWrapper,
                    hubble_path: str):
  """Drops the Hubble APK onto device (used when direct installation fails).

  Args:
    adb_wrapper: An AdbWrapper object that is used to issue ADB commands.
    hubble_path: The path to where Hubble resides on the host.

  """
  hubble_abs_path = os.path.abspath(hubble_path)
  # For some reasons, /storage/sdcard0 does not exist on all Xiaomi devices
  target_locations = [
      "/storage/sdcard0/Download/",
      "/sdcard/Download/"
  ]

  try_another = False
  for location in target_locations:
    if not adb_wrapper.push(hubble_abs_path, location):
      continue
    line = adb_wrapper.get_result()
    if line:
      if "error" in line or "fail" in line:
        try_another = True
    if not try_another:
      break


def install_hubble(adb_wrapper: syscall_wrapper.AdbWrapper,
                   args: argparse.Namespace,
                   logger: logging.Logger) -> bool:
  """Performs installation of Hubble via "adb install".

  Args:
    adb_wrapper: An AdbWrapper object that is used to issue ADB commands.
    args: The arguments object used in the following way:
          .hubble: To be read from to determine hubble's path
    logger: A logger object to log debug or error messages.

  Returns:
    A boolean indicating the success of the installation process.
  """
  hubble_abs_path = os.path.abspath(args.hubble)
  if not os.path.exists(hubble_abs_path):
    msg = "{} does not exist!".format(args.hubble)
    logger.error(msg)
    adb_wrapper.error_message = msg
    return False

  if not os.path.isfile(hubble_abs_path):
    msg = "{} is not a file".format(args.hubble)
    logger.error(msg)
    adb_wrapper.error_message = msg
    return False

  # do the actual installation by calling adb install
  if not adb_wrapper.install(hubble_abs_path):
    if not getattr(adb_wrapper, "error_message", None):
      adb_wrapper.error_message = "adb install failed"
    return False

  # sometimes, the return code states that installation is successful, but
  # in actuality there may still be some other failure(s).
  for l in adb_wrapper.get_result():
    logger.debug("installation result: {}".format(l))
    if "fail" in l.lower():
      adb_wrapper.error_message = l.strip()
      return False

  return True


def remove_previous_installation(adb_wrapper):
  return adb_wrapper.uninstall(HUBBLE_PACKAGE_NAME)


def launch_hubble(adb_wrapper):
  return adb_wrapper.am_start(action_name=None,
                              extra_string=None,
                              package_name=HUBBLE_PACKAGE_NAME,
                              component_name="{0}.MainActivity".format(
                                  HUBBLE_PACKAGE_NAME))


def terminate_logcat(buffer, logger):
  if HUBBLE_LOGCAT_TAG in buffer and HUBBLE_RESULT_STRING in buffer:
    logger.debug("Execution is done! Extracting result location...")
    comps = buffer.split()
    logger.debug("comps: {}".format(comps))
    results_dir = comps[-1]
    logger.debug("results dir: {}".format(results_dir))
    return results_dir
  return None


def wait_for_results(adb_wrapper, logger):
  logger.info("Waiting for results from Hubble execution...")
  patterns = ["HUBBLE:W", "*:S"]
  return adb_wrapper.logcat_find(patterns, terminate_logcat)


def _retry_apk_extraction(adb_wrapper: syscall_wrapper.AdbWrapper,
                          retry_packages_dict: dict[str, str],
                          apks_dir: str,
                          logger: logging.Logger) -> dict[str, str]:
  """Retries APK extraction using some hacks.

  The strategy here is to try to copy the APK to a different location
  such as /data/local/tmp and then copying from the new location
  instead.

  Args:
    adb_wrapper: An AdbWrapper instance.
    retry_packages_dict: A dictionary mapping package name to install
                         location on device to be retried.
    apks_dir: A string representing the umbrella apks/ directory where
              apks will be extracted into.
    logger: A logger object to log debug or error messages.

  Returns:
    A dictionary listing APKs that failed to be extracted.
  """
  failed_packages_dict = dict()
  for pkg_name in retry_packages_dict:
    target_dir = os.path.abspath(os.path.join(apks_dir, pkg_name))
    os.makedirs(target_dir, exist_ok=True)

    # first, copy the APK to a "safe" location on device
    tmp_dir = "/data/local/tmp"
    install_location = retry_packages_dict[pkg_name]
    cp_cmd = ["cp", install_location, tmp_dir]
    if not adb_wrapper.shell(cp_cmd):
      logger.warning("Failed to copy %s into %s.", install_location,
                     tmp_dir)
      failed_packages_dict[pkg_name] = install_location
      os.rmdir(target_dir)
      continue

    # then, pull the APK from the "safe" location
    apk_filename = os.path.basename(install_location)
    new_apk_filepath = os.path.join(tmp_dir, apk_filename)
    if not adb_wrapper.pull(new_apk_filepath, target_dir):
      logger.debug("Failed to pull %s from %s", pkg_name, new_apk_filepath)
      os.rmdir(target_dir)
      failed_packages_dict[pkg_name] = install_location
      continue

    # after successful extraction, delete the tmp copy of the file.
    rm_cmd = ["rm", new_apk_filepath]
    adb_wrapper.shell(rm_cmd)

  return failed_packages_dict


def extract_apks_from_device(adb_wrapper: syscall_wrapper.AdbWrapper,
                             packages_file_path: str,
                             apks_dir: str,
                             logger: logging.Logger,
                             preinstalled_only: bool = False) -> dict[str, str]:
  """Extracts APKs from device according to a list.

  APKs that are enumerated in a config (JSON) file are extracted
  to a local directory.
  Note that this excludes the Hubble APK itself.

  Args:
    adb_wrapper: An AdbWrapper instance.
    packages_file_path: A string pointing to the location of a packages.txt
                        file containing a list of packages to be extracted.
    apks_dir: The umbrella apks/ directory where apps will be
              extracted into.
    logger: A logger object to log debug or error messages.
    preinstalled_only: Whether the input file is preinstalled_packages.txt
                       (expects 'preinstalledPackages' key instead of 'packages').

  Returns:
    A dictionary listing APKs that failed to be extracted. An empty dict is
    return if there is no errors, or that there is nothing to be extracted.
  """
  if not apks_dir:
    logger.info("APKs dir is empty.")
    return dict()
  logger.debug("apks_dir: {}".format(apks_dir))

  if not packages_file_path:
    logger.error("packages_file_path is empty.")
    return dict()

  if not os.path.isfile(packages_file_path):
    logger.error("{} is an invalid file path.".format(packages_file_path))
    return dict()

  # Read in the file and convert the content into a JSON object
  packages_buff = ""
  with open(packages_file_path, "r") as f_in:
    packages_buff = f_in.read()
  try:
    packages_json = json.loads(packages_buff)
  except json.JSONDecodeError:
    logger.error("Failed to parse JSON from %s.", packages_file_path)
    return dict()

  if not isinstance(packages_json, dict):
    logger.error("Expected a JSON object in %s.", packages_file_path)
    return dict()

  expected_key = "preinstalledPackages" if preinstalled_only else "packages"
  packages_list = packages_json.get(expected_key)
  if not isinstance(packages_list, list):
    logger.error("No valid '%s' list found in %s.",
                 expected_key, packages_file_path)
    return dict()

  failed_packages_dict = dict()
  extracted_count = 0
  for package_json in packages_list:
    if (not isinstance(package_json, dict) or
        "name" not in package_json or
        "installLocation" not in package_json):
      logger.error("Malformed package entry in %s: %s",
                   packages_file_path, package_json)
      continue
    package_name = package_json["name"]

    package_install_location = package_json["installLocation"]
    target_dir = os.path.abspath(os.path.join(apks_dir, package_name))
    os.makedirs(target_dir, exist_ok=True)
    extracted_count += 1
    if not adb_wrapper.pull(package_install_location, target_dir):
      logger.debug("Failed to pull %s from %s", package_name,
                   package_install_location)
      # delete newly created empty directory
      os.rmdir(target_dir)
      extracted_count -= 1
      failed_packages_dict[package_name] = package_install_location

  failed_retry_packages_dict = _retry_apk_extraction(adb_wrapper,
                                                     failed_packages_dict,
                                                     apks_dir,
                                                     logger)
  retry_success_count = (len(failed_packages_dict) -
                         len(failed_retry_packages_dict))
  extracted_count += retry_success_count

  logger.info("Successfully extracted %d packages (excluding Hubble).",
              extracted_count)
  logger.info("%d packages failed to be extracted.",
              len(failed_retry_packages_dict))

  return failed_retry_packages_dict


def write_dict_as_json_to_file(in_dict, file_path: str):
  """Writes a dict as JSON string to file.

  Args:
    in_dict: A dictionary containing (key, pair) values to be written.
    file_path: A string representing a valid path to a file to be written.
  """
  with open(file_path, "w") as f_out:
    f_out.write(json.dumps(in_dict, indent=2))


# TODO: Rename/simplify classify_dir_using_build_fingerprint and remove
# references to "renewed method" vs. legacy ADB-format result categorization,
# as legacy categorization of Uraniborg results is no longer supported.
def classify_dir_using_build_fingerprint(
    adb_wrapper: syscall_wrapper.AdbWrapper,
    source: str,
    results_dir: str,
    extract_apks: bool,
    logger: logging.Logger,
    pull_preinstalled_only: bool = False,
    tmp_dir: str = "/tmp",
    events: Optional[EventEmitter] = None) -> Optional[str]:
  """Decides which directory in results/ to dump new result to.

  This is a renewed method that makes use of build fingerprint to do
  result classification. This method allows for better usability when a user
  is obtaining many results for the same device or build.

  Args:
    adb_wrapper: An AdbWrapper instance.
    source: the source directory (on target device) containing new results.
    results_dir: the umbrella results/ directory.
    extract_apks: A boolean indicating whether or not to also extract the APKs
                  from the target device.
    logger: A logger object to log debug or error messages.
    pull_preinstalled_only: A boolean indicating whether to only extract APKs
                            listed in preinstalled_packages.txt.
    tmp_dir: Temporary directory on host used for staging build.txt and
             adb backup artifacts. Defaults to "/tmp".
    events: An optional EventEmitter; used to report the `adb backup`
            confirmation that the user must give on the device.

  Returns:
    A string representing the final directory (on host) where results are pulled
    to. <code>None</code> is returned if any failure is encountered along the
    way.
  """
  # need to grab the build.txt to a tmp location
  tmp_file = os.path.join(tmp_dir, "device_build.txt")
  base_result_path = os.path.join(tmp_dir, "untarred_hubble_results")
  adb_pull_failed = False
  if not adb_wrapper.pull("{}/build.txt".format(source), tmp_file):
    logger.error("Failed to pull build.txt from device results dir.")
    adb_pull_failed = True

  if adb_pull_failed:
    logger.debug("Attempting to grab files using adb backup instead...")
    compressed_backup_filepath = os.path.join(tmp_dir, "hubble_results.ab")
    decompressed_backup_filepath = os.path.join(tmp_dir, "hubble_results.tar")
    logger.warning("Manual intervention required: Please select "
                   "`Back up my data` to proceed")
    with (events or EventEmitter()).prompt(
        adb_wrapper.device_serial_number, PROMPT_ADB_BACKUP_CONFIRM,
        "Select `Back up my data` on the device to proceed.",
        expects_input=False) as prompt:
      backed_up = adb_wrapper.backup(compressed_backup_filepath,
                                     HUBBLE_PACKAGE_NAME)
      if not backed_up:
        prompt.outcome = PROMPT_OUTCOME_FAILED
    if not backed_up:
      logger.error("Failed to use `adb backup` to pull result files.")
      return None

    # now we have to decompress the backup file
    logger.debug("Reading from %s into buffer...", compressed_backup_filepath)
    compressed_backup_filecontent = ""
    with open(compressed_backup_filepath, "rb") as f_in:
      compressed_backup_filecontent = f_in.read()

    # we'll need to skip 24 bytes to skip the Android backup header
    logger.debug("Decompressing backup file...")
    decompressed_content = zlib.decompress(compressed_backup_filecontent[24:])
    with open(decompressed_backup_filepath, "wb") as f_out:
      f_out.write(decompressed_content)

    tarfile_obj = io.BytesIO(decompressed_content)
    tar_obj = tarfile.open(fileobj=tarfile_obj)
    logger.debug("Extracting result files into %s", base_result_path)
    if hasattr(tarfile, "data_filter"):
      tar_obj.extractall(base_result_path, filter="data")
    else:
      tar_obj.extractall(base_result_path)

    # we overwrite tmp_file to reuse existing logic
    tmp_file = os.path.join(base_result_path, "apps", HUBBLE_PACKAGE_NAME,
                            "ef", "results", "build.txt")
    logger.debug("tmp_file: %s", tmp_file)

  build_info = ""
  with open(tmp_file, "r") as f_in:
    build_info = f_in.read()
  build_json = json.loads(build_info)
  build_fingerprint = build_json["buildInfo"][0]["fingerprint"]
  target_dir_parent = os.path.join(results_dir, build_fingerprint)

  if not os.path.exists(target_dir_parent):
    logger.debug("{} does not exist yet. Creating...".format(target_dir_parent))
    os.makedirs(target_dir_parent)

  target_dir = ""
  for i in range(1000):
    target_dir = os.path.join(target_dir_parent, "{0:03d}".format(i))
    logger.debug("Testing {} as target directory.".format(target_dir))
    if not os.path.exists(target_dir):
      logger.debug("{} does not exist yet! Using it!".format(target_dir))
      break

  os.makedirs(target_dir, exist_ok=True)

  apks_dir = ""
  if extract_apks:
    apks_dir = os.path.abspath(os.path.join(target_dir, "apks"))
    os.makedirs(apks_dir)

  pkg_filename = "preinstalled_packages.txt" if pull_preinstalled_only else "packages.txt"
  pkg_file_path = os.path.join(target_dir, "results", pkg_filename)

  if adb_pull_failed:
    source_dir = os.path.join(base_result_path, "apps",
                              HUBBLE_PACKAGE_NAME,
                              "ef",
                              "results")
    shutil.move(source_dir, target_dir)
    if pull_preinstalled_only and not os.path.exists(pkg_file_path):
      logger.error(
          "preinstalled_packages.txt not found in %s. "
          "--pull-preinstalled-apks-only requires Hubble >= 2.1.0.",
          os.path.join(target_dir, "results"))
      return None
    failed_extraction_dict = extract_apks_from_device(
        adb_wrapper, pkg_file_path,
        apks_dir, logger,
        preinstalled_only=pull_preinstalled_only)
    if failed_extraction_dict:
      write_dict_as_json_to_file(failed_extraction_dict,
                                 os.path.join(apks_dir,
                                              "failed_extraction.txt"))
    return target_dir
  else:
    if adb_wrapper.pull(source, target_dir):
      if pull_preinstalled_only and not os.path.exists(pkg_file_path):
        logger.error(
            "preinstalled_packages.txt not found in %s. "
            "--pull-preinstalled-apks-only requires Hubble >= 2.1.0.",
            os.path.join(target_dir, "results"))
        return None
      failed_extraction_dict = extract_apks_from_device(
          adb_wrapper, pkg_file_path,
          apks_dir,
          logger,
          preinstalled_only=pull_preinstalled_only)
      if failed_extraction_dict:
        write_dict_as_json_to_file(failed_extraction_dict,
                                   os.path.join(apks_dir,
                                                "failed_extraction.txt"))
      return target_dir
  return None


def extract_results_and_apks(adb_wrapper: syscall_wrapper.AdbWrapper,
                             source: str,
                             destination: str,
                             logger: logging.Logger,
                             extract_apks=False,
                             pull_preinstalled_only=False,
                             tmp_dir: str = "/tmp",
                             events: Optional[EventEmitter] = None
                             ) -> Optional[str]:
  """Extracts results (and optionally APKs) from Hubble's execution.

  Args:
    adb_wrapper: An AdbWrapper object that is used to issue ADB commands.
    source: the path to where results live (on device).
    destination: the path to where results should be copied to (on host).
    logger: A logger object to log debug or error messages.
    extract_apks: A boolean indicating whether to also extract APKs from the
                  device or not. This is defaulted to False.
    pull_preinstalled_only: A boolean indicating whether to only extract APKs
                            from preinstalled_packages.txt.
    tmp_dir: Temporary directory on host used for staging build.txt and
             adb backup artifacts. Defaults to "/tmp".
    events: An optional EventEmitter, passed on to report manual intervention.

  Returns:
    A string representing the final directory (on host) where results are copied
    to. <code>None</code> is returned if any failure is encountered along the
    way.
  """
  results_dir = None
  if not destination:
    results_dir = os.path.join(os.getcwd(), "results")
  else:
    # filter user supplied path via normpath to eliminate trailing slash(es)
    basename = os.path.basename(os.path.normpath(destination))
    if basename != "results":
      results_dir = os.path.join(destination, "results")
    else:
      results_dir = destination

  results_dir = os.path.abspath(results_dir)
  logger.debug("results_dir: {}".format(results_dir))
  if os.path.exists(results_dir):
    if not os.path.isdir(results_dir):
      logger.error("Supplied (--output) path is invalid.")
      return None
  else:
    logger.debug("{} does not exist yet. Creating...".format(results_dir))
    os.makedirs(results_dir, exist_ok=True)

  return classify_dir_using_build_fingerprint(adb_wrapper,
                                              source,
                                              results_dir,
                                              extract_apks,
                                              logger,
                                              pull_preinstalled_only=pull_preinstalled_only,
                                              tmp_dir=tmp_dir,
                                              events=events)


def extract_selinux_policies(adb_wrapper: syscall_wrapper.AdbWrapper,
                             target_dir: str,
                             logger: logging.Logger):
  """Extracts SELinux policies from the device.

  Args:
    adb_wrapper: An AdbWrapper object that is used to issue ADB commands.
    target_dir: The path (on host) where results currently reside.
    logger: A logger object to log debug or error messages.
  """
  source_folders = [
      "/system/etc/selinux",
      "/vendor/etc/selinux"
  ]
  target_folders = [
      os.path.join(target_dir, "selinux/system/"),
      os.path.join(target_dir, "selinux/vendor/")
  ]

  logger.debug("Creating system and vendor target folders...")
  for folder in target_folders:
    os.makedirs(folder, exist_ok=True)

  for i in range(len(source_folders)):
    ls_cmd = ["ls", source_folders[i]]
    if not adb_wrapper.shell(ls_cmd):
      logger.warning("Failed to fully stat contents in %s", source_folders[i])

    # I'm forced to copy item-by-item because sometimes, the entire 'pull'
    # operation when one file fails to be copied, leaving other files that can
    # be copied uncopied.
    # NOTE that this doesn't yet deal with errors that occur more than 1 level
    # deep!
    for item in adb_wrapper.get_result():
      source_location = os.path.join(source_folders[i], item)
      logger.debug("source_location: %s", source_location)
      status = adb_wrapper.pull(source_location, target_folders[i])
      if not status:
        logger.warning("Failed to pull %s. Continuing...", source_location)


def ensure_android_sdk(hubble_project_dir: str, logger: logging.Logger) -> bool:
  """Ensures that Android SDK location is set for Gradle.

  Args:
    hubble_project_dir: Path to the Hubble Android project directory.
    logger: A logger object to log debug or error messages.

  Returns:
    True if SDK location is set and valid, False otherwise.
  """
  if os.environ.get("ANDROID_HOME"):
    logger.debug("ANDROID_HOME is set to %s", os.environ.get("ANDROID_HOME"))
    return True
  if os.environ.get("ANDROID_SDK_ROOT"):
    logger.debug("ANDROID_SDK_ROOT is set to %s", os.environ.get("ANDROID_SDK_ROOT"))
    return True

  local_props_path = os.path.join(hubble_project_dir, "local.properties")
  if os.path.exists(local_props_path):
    with open(local_props_path, "r") as f:
      for line in f:
        if line.startswith("sdk.dir="):
          sdk_dir = line.split("=")[1].strip()
          logger.debug("Found sdk.dir in local.properties: %s", sdk_dir)
          if os.path.exists(sdk_dir):
            return True
          else:
            logger.warning("sdk.dir in local.properties points to non-existent directory: %s", sdk_dir)

  default_locations = []
  if sys.platform == "darwin":
    default_locations.append(os.path.expanduser("~/Library/Android/sdk"))
  elif sys.platform == "linux":
    default_locations.append(os.path.expanduser("~/Android/Sdk"))

  sdk_path = None
  for loc in default_locations:
    if os.path.exists(loc):
      logger.info("Auto-detected Android SDK at %s", loc)
      sdk_path = loc
      break

  if not sdk_path:
    logger.error("Android SDK location not found in environment or default locations.")
    logger.error("Please set the ANDROID_HOME environment variable to point to your Android SDK installation.")
    return False

  logger.info("Writing sdk.dir to %s", local_props_path)
  lines = []
  if os.path.exists(local_props_path):
    with open(local_props_path, "r") as f:
      lines = f.read().splitlines()

  lines = [l for l in lines if not l.strip().startswith("sdk.dir=")]
  lines.append(f"sdk.dir={sdk_path}")

  with open(local_props_path, "w") as f:
    f.write("\n".join(lines) + "\n")

  return True


def rebuild_hubble(logger: logging.Logger) -> tuple[Optional[str], Optional[dict]]:
  """Rebuilds the Hubble debug APK with Gradle and refreshes prebuilts/APK/latest.

  Args:
    logger: A logger object to log debug or error messages.

  Returns:
    A tuple (apk_path, error). On success apk_path is the path of the
    refreshed "latest" symlink and error is None. On failure apk_path is None
    and error is a run_finished error dict (see _error).
  """
  script_dir = os.path.dirname(os.path.abspath(__file__))
  hubble_project_dir = os.path.abspath(os.path.join(script_dir, "../../AndroidStudioProject/Hubble"))
  if not ensure_android_sdk(hubble_project_dir, logger):
    msg = "Failed to (re)build Hubble APK: Android SDK not found."
    logger.error(msg)
    return None, _error(REASON_ANDROID_SDK_NOT_FOUND, msg)
  gradlew_path = os.path.join(hubble_project_dir, "gradlew")

  logger.info("Running 'gradlew assembleDebug' in %s", hubble_project_dir)
  sw = SyscallWrapper(logger)
  sw.call_returnable_command([gradlew_path, "assembleDebug"], cwd=hubble_project_dir)
  if sw.error_occured:
    logger.error("Failed to (re)build Hubble APK: [%d] %s", sw.return_code, sw.error_message)
    return None, _error(
        REASON_HUBBLE_BUILD_FAILED,
        "Failed to (re)build Hubble APK: [{}] {}".format(
            sw.return_code, sw.error_message))

  for line in sw.result_final:
    logger.debug("Gradle output: %s", line)

  latest_symlink_path = os.path.abspath(os.path.join(script_dir, "../../prebuilts/APK/latest"))
  os.makedirs(os.path.dirname(latest_symlink_path), exist_ok=True)
  if os.path.exists(latest_symlink_path) or os.path.islink(latest_symlink_path):
    logger.debug("Removing old symlink: %s", latest_symlink_path)
    try:
      os.remove(latest_symlink_path)
    except Exception as e:
      logger.error("Failed to remove old symlink %s: %s", latest_symlink_path, e)
      return None, _error(
          REASON_HUBBLE_BUILD_FAILED,
          "Failed to remove old symlink {}: {}".format(latest_symlink_path, e))

  symlink_target = "../../AndroidStudioProject/Hubble/app/build/outputs/apk/debug/app-debug.apk"

  logger.info("Creating new symlink 'latest' -> %s", symlink_target)
  try:
    os.symlink(symlink_target, latest_symlink_path)
  except Exception as e:
    logger.error("Failed to create symlink %s: %s", latest_symlink_path, e)
    return None, _error(
        REASON_HUBBLE_BUILD_FAILED,
        "Failed to create symlink {}: {}".format(latest_symlink_path, e))

  return latest_symlink_path, None


def process_device(target_device, args: argparse.Namespace,
                   logger: logging.Logger, events: EventEmitter,
                   state: RunState) -> DeviceResult:
  """Observes one selected device, from installing Hubble to the proof check.

  Emits device_started and, however processing ends, device_finished.
  Exceptions are logged and reported as the device's error; KeyboardInterrupt
  and other BaseExceptions are reported, then re-raised.

  Args:
    target_device: A DeviceInfo from AdbWrapper.devices().
    args: Parsed arguments from parse_arguments().
    logger: A logger object to log debug or error messages.
    events: Where to report progress events. May be a disabled emitter.
    state: State shared with the other devices of this run.

  Returns:
    The device's outcome.
  """
  serial = target_device.serial_number
  progress = _DeviceProgress()
  events.emit("device_started", device=serial)
  try:
    _observe_device(target_device, args, logger, events, state, progress)
  except Exception as e:
    logger.exception("Unexpected error while processing device %s: %s",
                     serial, e)
    progress.error = _error(REASON_UNEXPECTED_ERROR,
                            "{}: {}".format(type(e).__name__, e))
    progress.collection_error = True
  except BaseException as e:
    # KeyboardInterrupt and other non-Exception exits bypass the handler
    # above. Record them before propagating, so the device_finished event
    # in the finally block does not report an interrupted device as a
    # success when its results were already collected.
    progress.error = _interruption_error(e)
    progress.collection_error = True
    raise
  finally:
    result = progress.result()
    events.device_finished(serial, result.status,
                           results_dir=result.results_dir,
                           error=result.error)
  return result


def _observe_device(target_device, args: argparse.Namespace,
                    logger: logging.Logger, events: EventEmitter,
                    state: RunState, progress: _DeviceProgress):
  """The steps of process_device(); returns early when a step fails.

  Failures are recorded on progress rather than returned, so that
  process_device() can report them even when an exception cuts this short.
  """
  serial = target_device.serial_number
  if target_device.unauthorized:
    logger.error("Please authorize device with serial number %s for ADB via "
                 "device GUI.", serial)
    progress.error = _error(REASON_UNAUTHORIZED,
                            "ADB is not authorized on this device.")
    return

  # set up an adb_wrapper to be used throughout for this target device
  adb_wrapper = AdbWrapper(serial, logger)

  if is_hubble_installed(adb_wrapper, logger):
    logger.debug("Removing previous Hubble installation...")
    with events.step("uninstall_previous", serial) as s:
      if not remove_previous_installation(adb_wrapper):
        logger.error("Failed to remove previous Hubble installation.")
        progress.error = _error(REASON_UNINSTALL_FAILED, s.fail(
            "Failed to remove previous Hubble installation."))
        return

  with events.step("install_hubble", serial) as s:
    if is_xiaomi_phone(adb_wrapper, logger):
      logger.info("This is a Xiaomi phone.")
      adb_push_hubble(adb_wrapper, args.hubble)
      if not launch_xiaomi_file_explorer(adb_wrapper):
        logger.error("Failed to launch Xiaomi file explorer")
      if not wait_for_xiaomi_manual_install(adb_wrapper, serial, logger,
                                            events):
        progress.error = _error(REASON_STDIN_CLOSED, s.fail(
            "Standard input closed while waiting for manual Hubble "
            "installation."))
        return
    else:
      logger.info("This is not a Xiaomi phone. Regular workflow continues...")
      if not install_hubble(adb_wrapper, args, logger):
        logger.error("Error installing Hubble: %s", adb_wrapper.error_message)
        progress.error = _error(REASON_INSTALL_FAILED, s.fail(
            "Error installing Hubble: {}".format(adb_wrapper.error_message)))
        return

  with events.step("launch_hubble", serial) as s:
    clear_logcat(adb_wrapper)
    if not launch_hubble(adb_wrapper):
      logger.error("Failed to launch Hubble: %s", adb_wrapper.error_message)
      progress.error = _error(REASON_LAUNCH_FAILED, s.fail(
          "Failed to launch Hubble: {}".format(adb_wrapper.error_message)))
      return

  with events.step("wait_for_results", serial) as s:
    results_source = wait_for_results(adb_wrapper, logger)
    if not results_source:
      logger.error("Failed to obtain results from Hubble execution.")
      progress.error = _error(REASON_NO_RESULTS, s.fail(
          "Failed to obtain results from Hubble execution."))
      return

  with events.step("extract_results", serial) as s:
    extract_apks = (args.pull_all_apks is not None) or args.pull_preinstalled_apks_only
    with tempfile.TemporaryDirectory() as device_tmp_dir:
      results_dir = extract_results_and_apks(
          adb_wrapper,
          results_source,
          args.output,
          logger,
          extract_apks,
          pull_preinstalled_only=args.pull_preinstalled_apks_only,
          tmp_dir=device_tmp_dir,
          events=events)

    if not results_dir:
      logger.error("Failed to extract results from target device (%s).",
                   serial)
      progress.error = _error(REASON_EXTRACT_FAILED, s.fail(
          "Failed to extract results from device."))
      return

  with events.step("extract_selinux", serial):
    extract_selinux_policies(adb_wrapper, results_dir, logger)
  progress.results_dir = results_dir

  if not args.perform_inclusion_proof_check:
    return
  pkg_filename = (
      "preinstalled_packages.txt"
      if args.check_preinstalled_only
      else "packages.txt"
  )
  packages_txt_path = os.path.join(results_dir, "results", pkg_filename)
  if args.check_preinstalled_only and not os.path.isfile(packages_txt_path):
    with events.step("inclusion_proof_check", serial) as s:
      logger.error(
          "preinstalled_packages.txt not found at %s (extracted results at %s). "
          "--check_preinstalled_only requires Hubble >= 2.1.0.",
          packages_txt_path, results_dir)
      progress.error = _error(
          REASON_INCLUSION_PROOF_CHECK_INCOMPLETE,
          s.fail("preinstalled_packages.txt not found; "
                 "--check_preinstalled_only requires Hubble >= 2.1.0."))
    progress.check_incomplete = True
    return
  if (not args.no_prefetch and not state.prefetched and
      os.path.isfile(packages_txt_path)):
    with events.step("inclusion_proof_prefetch", serial) as s:
      state.prefetched = inclusion_proof_check.prefetch_log_entries(
          args.verifier_path,
          logger,
          cache_dir=args.cache_dir,
          concurrency=args.cache_prefetch_concurrency,
          timeout=args.cache_prefetch_timeout)
      if not state.prefetched:
        s.fail("Pre-fetching failed; falling back to on-demand fetching.")
  with events.step("inclusion_proof_check", serial) as s:
    if not inclusion_proof_check.perform_inclusion_proof_check(
        args.verifier_path,
        packages_txt_path,
        logger,
        cache_dir=args.cache_dir,
        concurrency=args.cache_prefetch_concurrency,
        timeout=args.cache_prefetch_timeout,
        prefetch=False,
        preinstalled_only=args.check_preinstalled_only,
        progress=events.progress_reporter("inclusion_proof_check", serial)):
      progress.check_incomplete = True
      # False means the check could not complete (bad input or unwritable
      # output), not that some splits are absent from the log; per-split
      # results are in the *_signal.txt output.
      progress.error = _error(REASON_INCLUSION_PROOF_CHECK_INCOMPLETE,
                              s.fail("Inclusion proof check could not "
                                     "complete."))


def print_summary(serials, outcomes: dict, missing_serials,
                  logger: logging.Logger) -> dict:
  """Logs the final outcome line(s) for each device.

  Args:
    serials: Serials in the order to report them.
    outcomes: serial -> DeviceResult, for every serial in serials.
    missing_serials: Serials requested via --serial that were not connected.
    logger: A logger object to log messages.

  Returns:
    The run_finished summary: serial -> {status, results_dir?}.
  """
  missing = set(missing_serials)
  summary = {}
  for device in serials:
    outcome = outcomes[device]
    status = outcome.status
    summary[device] = {"status": status}
    if outcome.results_dir is not None:
      summary[device]["results_dir"] = outcome.results_dir

    if device in missing:
      logger.error(
          "FAILED: Requested device %s is not connected (exiting 1).",
          device)
      continue
    if status == STATUS_FAILED:
      logger.error(
          "FAILED: Hubble data collection failed on connected device %s "
          "(exiting 1).",
          device)
      continue
    if status == STATUS_PARTIAL_ERROR:
      logger.warning(
          "PARTIAL SUCCESS: Hubble data collection succeeded on connected "
          "device %s, but an unexpected error occurred during post-collection "
          "processing (exiting 1).",
          device)
    elif status == STATUS_PARTIAL_CHECK_INCOMPLETE:
      logger.warning(
          "PARTIAL SUCCESS: Hubble data collection succeeded on connected "
          "device %s, but inclusion proof verification failed (exiting 1).",
          device)
    else:
      logger.info("SUCCESS! Hubble was successfully deployed and executed on "
                  "connected device %s.", device)
    logger.info("Hubble output files can be found at: %s", outcome.results_dir)
  return summary


def run(args: argparse.Namespace, logger: logging.Logger,
        events: EventEmitter) -> int:
  """Runs the observation workflow.

  Emits run_finished on every path that returns.

  Args:
    args: Parsed arguments from parse_arguments().
    logger: A logger object to log debug or error messages.
    events: Where to report progress events. May be a disabled emitter.

  Returns:
    The process exit code. Early exits (before any device is processed)
    return 0, as they always have; run_finished.error describes them.
  """
  events.emit("run_started", argv=sys.argv[1:], pid=os.getpid())
  for warning in validate_argument_combinations(args):
    logger.warning(warning)

  def early_exit(reason: str, message: str) -> int:
    events.finish_run(0, error=_error(reason, message))
    return 0

  if not supported_platform(logger):
    logger.error("Sorry, your OS is currently unsupported for this script.")
    return early_exit(REASON_UNSUPPORTED_PLATFORM,
                      "Unsupported platform: {}".format(sys.platform))

  if args.hubble is None:
    logger.info("-H flag not used. Rebuilding Hubble...")
    with events.step("build_hubble") as s:
      hubble_path, build_error = rebuild_hubble(logger)
      if build_error:
        s.fail(build_error["message"])
    if build_error:
      events.finish_run(0, error=build_error)
      return 0
    args.hubble = hubble_path

  with events.step("verify_hubble") as s:
    if not verify_hubble(args, logger):
      s.fail("Hubble APK to be installed must have the .apk extension.")
  if s.failed:
    return early_exit(REASON_INVALID_HUBBLE_APK, s.message)

  with events.step("check_adb") as s:
    if not adb_installed(logger):
      s.fail("adb was not found on this system.")
  if s.failed:
    return early_exit(REASON_ADB_NOT_FOUND, s.message)

  with events.step("start_adb_server") as s:
    if not AdbWrapper.start_server(logger):
      s.fail("Failed to start the adb server.")
  if s.failed:
    return early_exit(REASON_ADB_SERVER_FAILED, s.message)

  with events.step("list_devices") as s:
    listed_devices = AdbWrapper.devices(logger)
    if listed_devices is None:
      s.fail("`adb devices` failed.")
  connected_devices = listed_devices or []
  # With --serial, fall through: every requested serial is then reported as
  # missing, FAILED in the summary, and the run exits 1.
  if not connected_devices and args.serial is None:
    logger.error("No devices connected!")
    if listed_devices is None:
      return early_exit(REASON_ADB_DEVICES_FAILED, "`adb devices` failed.")
    return early_exit(REASON_NO_DEVICES, "No devices connected!")

  logger.debug("There are %d connected device(s)", len(connected_devices))
  target_devices, missing_serials = select_target_devices(
      connected_devices, args.serial, logger)
  # Without --serial every connected device is observed; warn in case that
  # was not intended. With --serial the user has already chosen explicitly.
  if args.serial is None and len(connected_devices) > 1:
    logger.warning("More than 1 device connected!")

  events.emit("devices",
              devices=[_device_to_event(d) for d in connected_devices],
              selected=[d.serial_number for d in target_devices],
              missing=missing_serials)
  outcomes = {}
  for serial in missing_serials:
    outcomes[serial] = DeviceResult(
        STATUS_FAILED, error=_error(REASON_NOT_CONNECTED,
                                    "Requested device is not connected."))
    events.device_finished(serial, STATUS_FAILED,
                           error=outcomes[serial].error)

  state = RunState()
  has_errors = bool(missing_serials)
  for target_device in target_devices:
    result = process_device(target_device, args, logger, events, state)
    # Decided per device, not from `outcomes`: two connected devices can
    # share a serial, and the second must not hide the first one's failure.
    has_errors = has_errors or result.status != STATUS_SUCCESS
    outcomes[target_device.serial_number] = result

  # Summarise in the order devices were requested (or discovered, without
  # --serial), including requested serials that were never connected.
  summary_serials = list(dict.fromkeys(
      args.serial if args.serial is not None
      else [d.serial_number for d in connected_devices]))
  summary = print_summary(summary_serials, outcomes, missing_serials, logger)

  exit_code = 1 if has_errors else 0
  events.finish_run(exit_code, summary=summary)
  return exit_code


def main():
  args = parse_arguments()
  logger = set_up_logging(args)

  events = EventEmitter(logger=logger)
  if args.events is not None:
    try:
      events = EventEmitter(open_event_stream(args.events), logger=logger)
    except OSError as e:
      logger.error("Cannot open --events destination %s: %s", args.events, e)
      sys.exit(1)

  # SIGTERM (how CI timeouts and cancellations usually stop a process) would
  # otherwise kill the script without a run_finished event. While events are
  # being written, turn it into an exception so the run can report itself,
  # then die by SIGTERM anyway so the parent sees the usual exit status.
  # Without --events, SIGTERM handling is left untouched.
  terminated = False
  with (termination.sigterm_raises() if events.enabled
        else contextlib.nullcontext()):
    try:
      exit_code = run(args, logger, events)
    except termination.Terminated:
      events.finish_run(128 + signal.SIGTERM, error=_error(
          REASON_TERMINATED, "Terminated by SIGTERM."))
      terminated = True
    except KeyboardInterrupt:
      events.finish_run(130, error=_error(REASON_INTERRUPTED,
                                              "Interrupted by user."))
      raise
    except BaseException as e:
      events.finish_run(1, error=_error(
          REASON_UNEXPECTED_ERROR, "{}: {}".format(type(e).__name__, e)))
      raise
    finally:
      events.close()

  if terminated:
    termination.die_by_sigterm(logger)
    return
  if exit_code:
    sys.exit(exit_code)


if __name__ == "__main__":
  main()
