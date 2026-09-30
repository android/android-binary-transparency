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

"""Unit tests for automate_observation.py's --events progress stream."""

import contextlib
import datetime
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import textwrap
import time
from unittest import mock

import pytest

# Ensure uraniborg/scripts/python is on sys.path
SCRIPT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, SCRIPT_DIR)

import automate_observation
import termination
# Shared fixture and helpers for driving main() with every collaborator mocked.
from test_automate_observation import _make_mock_device  # pylint: disable=g-importing-member
from test_automate_observation import _set_argv  # pylint: disable=g-importing-member
from test_automate_observation import serial_main_mocks  # pylint: disable=unused-import,g-importing-member

EventEmitter = automate_observation.EventEmitter

_FIXED_TIME = datetime.datetime(2026, 1, 2, 3, 4, 5, 678000,
                                tzinfo=datetime.timezone.utc)


def _emitter(stream=None, logger=None):
  return EventEmitter(stream if stream is not None else io.StringIO(),
                      logger=logger, clock=lambda: _FIXED_TIME)


def _parse(stream: io.StringIO) -> list[dict]:
  return [json.loads(line) for line in stream.getvalue().splitlines()]


def _read_events(path: Path) -> list[dict]:
  return [json.loads(line) for line in path.read_text().splitlines()]


def _steps(events: list[dict], device=None) -> list[tuple[str, str]]:
  return [(e["step"], e["state"]) for e in events
          if e["type"] == "step" and e.get("device") == device]


def _of_type(events: list[dict], event_type: str) -> list[dict]:
  return [e for e in events if e["type"] == event_type]


# --- EventEmitter ---------------------------------------------------------------


def test_emitter_without_stream_is_a_noop():
  emitter = EventEmitter()
  assert not emitter.enabled
  emitter.emit("anything", x=1)
  with emitter.step("s") as s:
    s.fail("nope")
  emitter.finish_run(1)
  emitter.close()  # must not raise


def test_emit_envelope_drops_none_and_flushes_each_event():
  stream = mock.Mock(wraps=io.StringIO())
  emitter = EventEmitter(stream, clock=lambda: _FIXED_TIME)

  emitter.emit("thing", device="D1", results_dir=None, count=2)
  assert stream.flush.call_count == 1
  emitter.emit("other")
  assert stream.flush.call_count == 2

  lines = stream.getvalue().splitlines()
  assert json.loads(lines[0]) == {
      "v": 1, "ts": "2026-01-02T03:04:05.678Z", "type": "thing",
      "device": "D1", "count": 2,
  }
  assert json.loads(lines[1]) == {
      "v": 1, "ts": "2026-01-02T03:04:05.678Z", "type": "other"}


def test_emit_write_failure_warns_once_and_disables():
  stream = mock.Mock()
  stream.write.side_effect = BrokenPipeError("reader went away")
  logger = mock.Mock()
  emitter = EventEmitter(stream, logger=logger)

  emitter.emit("a")
  emitter.emit("b")

  assert not emitter.enabled
  assert stream.write.call_count == 1
  logger.warning.assert_called_once()


def test_step_reports_finished_failed_and_exceptions():
  stream = io.StringIO()
  emitter = _emitter(stream)

  with emitter.step("ok", device="D1"):
    pass
  with emitter.step("soft_fail") as s:
    assert s.fail("went wrong") == "went wrong"
  with pytest.raises(RuntimeError):
    with emitter.step("boom", device="D1"):
      raise RuntimeError("kaput")

  events = _parse(stream)
  assert [(e["step"], e["state"], e.get("device")) for e in events] == [
      ("ok", "started", "D1"), ("ok", "finished", "D1"),
      ("soft_fail", "started", None), ("soft_fail", "failed", None),
      ("boom", "started", "D1"), ("boom", "failed", "D1"),
  ]
  assert "message" not in events[1]
  assert events[3]["message"] == "went wrong"
  assert events[5]["message"] == "RuntimeError: kaput"
  for e in events[1::2]:
    assert isinstance(e["duration_ms"], int) and e["duration_ms"] >= 0
  for e in events[0::2]:
    assert "duration_ms" not in e


def test_step_reports_finished_when_body_continues_a_loop():
  """`continue` inside the with-block must still close the step."""
  stream = io.StringIO()
  emitter = _emitter(stream)
  for _ in range(1):
    with emitter.step("loop") as s:
      s.fail("skipped")
      continue
  assert [(e["step"], e["state"]) for e in _parse(stream)] == [
      ("loop", "started"), ("loop", "failed")]


class _FakeMonotonic:

  def __init__(self):
    self.now = 100.0

  def __call__(self):
    return self.now


def _progress(events: list[dict]) -> list[tuple[int, int]]:
  return [(e["done"], e["total"]) for e in _of_type(events, "step_progress")]


def test_progress_reporter_event_shape():
  stream = io.StringIO()
  emitter = EventEmitter(stream, clock=lambda: _FIXED_TIME)
  emitter.progress_reporter("inclusion_proof_check", "D1")(0, 5)
  emitter.progress_reporter("other_step")(0, 2)
  assert _parse(stream) == [
      {"v": 1, "ts": "2026-01-02T03:04:05.678Z", "type": "step_progress",
       "step": "inclusion_proof_check", "device": "D1", "done": 0,
       "total": 5},
      {"v": 1, "ts": "2026-01-02T03:04:05.678Z", "type": "step_progress",
       "step": "other_step", "done": 0, "total": 2},
  ]


def test_progress_reporter_throttles_but_reports_first_and_last():
  stream = io.StringIO()
  clock = _FakeMonotonic()
  emitter = EventEmitter(stream, clock=lambda: _FIXED_TIME, monotonic=clock)
  report = emitter.progress_reporter("s", "D1", interval=2.0)

  report(0, 10)       # first: reported
  report(1, 10)       # too soon
  clock.now += 1.9
  report(2, 10)       # still too soon
  clock.now += 0.1
  report(3, 10)       # 2 s after the last event: reported
  report(4, 10)       # too soon
  clock.now += 5
  report(5, 10)       # reported
  report(5, 10)       # same done again: never reported
  report(10, 10)      # last: always reported, even right away
  clock.now += 5
  report(10, 10)      # repeat of the last: not reported

  assert _progress(_parse(stream)) == [(0, 10), (3, 10), (5, 10), (10, 10)]


def test_progress_reporter_empty_step_reports_once():
  stream = io.StringIO()
  report = _emitter(stream).progress_reporter("s")
  report(0, 0)
  assert _progress(_parse(stream)) == [(0, 0)]


def test_progress_reporter_without_stream_is_a_noop():
  report = EventEmitter().progress_reporter("s", "D1")
  report(0, 3)
  report(3, 3)  # must not raise


def test_finish_run_is_emitted_once_with_ok_semantics():
  stream = io.StringIO()
  emitter = _emitter(stream)
  emitter.finish_run(0, summary={"D1": {"status": "success"}})
  emitter.finish_run(1, error={"reason": "x", "message": "y"})  # ignored
  (event,) = _parse(stream)
  assert event["type"] == "run_finished"
  assert event["exit_code"] == 0
  assert event["ok"] is True
  assert event["summary"] == {"D1": {"status": "success"}}
  assert "error" not in event

  for exit_code, error, ok in [(1, None, False),
                               (0, {"reason": "r", "message": "m"}, False)]:
    stream = io.StringIO()
    _emitter(stream).finish_run(exit_code, error=error)
    (event,) = _parse(stream)
    assert event["ok"] is ok
    assert event["summary"] == {}


def test_device_to_event_skips_empty_and_non_string_attributes():
  dev = automate_observation.syscall_wrapper.DeviceInfo()
  dev.serial_number = "S1"
  dev.model_name = "Pixel_9"
  dev.product_name = ""
  assert automate_observation._device_to_event(dev) == {
      "serial": "S1", "unauthorized": False, "model": "Pixel_9"}
  # Mock devices (as used throughout the tests) must not leak Mock reprs.
  assert automate_observation._device_to_event(_make_mock_device("S2")) == {
      "serial": "S2", "unauthorized": False}


# --- main() with --events --------------------------------------------------------


def test_main_events_full_run_with_missing_serial(
    serial_main_mocks, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
):
  m = serial_main_mocks
  unauthorized = _make_mock_device("DEV_UNAUTH")
  unauthorized.unauthorized = True
  m["AdbWrapper"].devices.return_value = [
      _make_mock_device("DEV1"), unauthorized, _make_mock_device("DEV_OTHER")]
  events_path = tmp_path / "events.jsonl"
  _set_argv(monkeypatch, "--events", str(events_path),
            "-s", "DEV1", "-s", "GONE", "-s", "DEV_UNAUTH")

  with pytest.raises(SystemExit) as exc_info:
    automate_observation.main()
  assert exc_info.value.code == 1

  events = _read_events(events_path)
  assert all(e["v"] == 1 and e["ts"].endswith("Z") for e in events)
  assert events[0]["type"] == "run_started"
  assert events[0]["argv"][-6:] == [
      "-s", "DEV1", "-s", "GONE", "-s", "DEV_UNAUTH"]
  assert events[-1]["type"] == "run_finished"
  assert len(_of_type(events, "run_finished")) == 1

  assert _steps(events) == [
      ("verify_hubble", "started"), ("verify_hubble", "finished"),
      ("check_adb", "started"), ("check_adb", "finished"),
      ("start_adb_server", "started"), ("start_adb_server", "finished"),
      ("list_devices", "started"), ("list_devices", "finished"),
  ]

  (devices,) = _of_type(events, "devices")
  assert devices["devices"] == [
      {"serial": "DEV1", "unauthorized": False},
      {"serial": "DEV_UNAUTH", "unauthorized": True},
      {"serial": "DEV_OTHER", "unauthorized": False},
  ]
  assert devices["selected"] == ["DEV1", "DEV_UNAUTH"]
  assert devices["missing"] == ["GONE"]

  # Every selected or missing serial gets exactly one device_finished;
  # missing ones get no device_started.
  assert [e["device"] for e in _of_type(events, "device_started")] == [
      "DEV1", "DEV_UNAUTH"]
  finished = {e["device"]: e for e in _of_type(events, "device_finished")}
  assert set(finished) == {"GONE", "DEV1", "DEV_UNAUTH"}
  assert finished["GONE"]["status"] == "failed"
  assert finished["GONE"]["error"] == {
      "reason": "not_connected",
      "message": "Requested device is not connected."}
  assert finished["DEV1"]["status"] == "success"
  assert finished["DEV1"]["results_dir"] == "/tmp/out/DEV1"
  assert "error" not in finished["DEV1"]
  assert finished["DEV_UNAUTH"]["status"] == "failed"
  assert "results_dir" not in finished["DEV_UNAUTH"]
  assert finished["DEV_UNAUTH"]["error"]["reason"] == "unauthorized"
  assert "not authorized" in finished["DEV_UNAUTH"]["error"]["message"]

  assert _steps(events, "DEV1") == [
      ("install_hubble", "started"), ("install_hubble", "finished"),
      ("launch_hubble", "started"), ("launch_hubble", "finished"),
      ("wait_for_results", "started"), ("wait_for_results", "finished"),
      ("extract_results", "started"), ("extract_results", "finished"),
      ("extract_selinux", "started"), ("extract_selinux", "finished"),
  ]
  assert _steps(events, "DEV_UNAUTH") == []

  run_finished = events[-1]
  assert run_finished["exit_code"] == 1
  assert run_finished["ok"] is False
  assert "error" not in run_finished
  assert run_finished["summary"] == {
      "DEV1": {"status": "success", "results_dir": "/tmp/out/DEV1"},
      "GONE": {"status": "failed"},
      "DEV_UNAUTH": {"status": "failed"},
  }
  assert list(run_finished["summary"]) == ["DEV1", "GONE", "DEV_UNAUTH"]


def test_main_events_success_exits_0_with_ok(
    serial_main_mocks, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
):
  m = serial_main_mocks
  m["AdbWrapper"].devices.return_value = [_make_mock_device("DEV1")]
  events_path = tmp_path / "events.jsonl"
  _set_argv(monkeypatch, "--events", str(events_path))

  automate_observation.main()  # no SystemExit

  run_finished = _read_events(events_path)[-1]
  assert run_finished["type"] == "run_finished"
  assert run_finished["exit_code"] == 0
  assert run_finished["ok"] is True


def test_main_events_previous_install_and_install_failure(
    serial_main_mocks, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
):
  m = serial_main_mocks
  m["AdbWrapper"].devices.return_value = [_make_mock_device("DEV1")]
  m["is_hubble_installed"].return_value = True
  with mock.patch("automate_observation.remove_previous_installation",
                  return_value=True):
    m["install_hubble"].return_value = False
    events_path = tmp_path / "events.jsonl"
    _set_argv(monkeypatch, "--events", str(events_path))
    with pytest.raises(SystemExit):
      automate_observation.main()

  events = _read_events(events_path)
  install_failed = [e for e in events if e["type"] == "step"
                    and e["step"] == "install_hubble"
                    and e["state"] == "failed"]
  assert _steps(events, "DEV1") == [
      ("uninstall_previous", "started"), ("uninstall_previous", "finished"),
      ("install_hubble", "started"), ("install_hubble", "failed"),
  ]
  assert install_failed[0]["message"].startswith("Error installing Hubble:")
  (finished,) = _of_type(events, "device_finished")
  assert finished["status"] == "failed"
  assert finished["error"] == {"reason": "install_failed",
                               "message": install_failed[0]["message"]}


@pytest.mark.parametrize(
    "prefetch_ok, check_result, expected_status, expected_check_state",
    [
        (True, True, "success", "finished"),
        (False, True, "success", "finished"),
        (True, False, "partial_check_incomplete", "failed"),
        (True, RuntimeError("verifier crashed"), "partial_error", "failed"),
    ],
    ids=["verified", "prefetch_failed", "verification_failed", "crash"],
)
def test_main_events_inclusion_proof_outcomes(
    serial_main_mocks, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    prefetch_ok, check_result, expected_status, expected_check_state,
):
  m = serial_main_mocks
  m["AdbWrapper"].devices.return_value = [_make_mock_device("DEV1")]
  events_path = tmp_path / "events.jsonl"
  _set_argv(monkeypatch, "--events", str(events_path),
            "--perform_inclusion_proof_check", "--verifier_path=/v")
  check_kwargs = ({"side_effect": check_result}
                  if isinstance(check_result, Exception)
                  else {"return_value": check_result})
  with mock.patch("automate_observation.os.path.isfile", return_value=True), \
       mock.patch("inclusion_proof_check.prefetch_log_entries",
                  return_value=prefetch_ok), \
       mock.patch("inclusion_proof_check.perform_inclusion_proof_check",
                  **check_kwargs):
    if expected_status == "success":
      automate_observation.main()
    else:
      with pytest.raises(SystemExit):
        automate_observation.main()

  events = _read_events(events_path)
  steps = _steps(events, "DEV1")
  assert steps[-4:] == [
      ("inclusion_proof_prefetch", "started"),
      ("inclusion_proof_prefetch", "finished" if prefetch_ok else "failed"),
      ("inclusion_proof_check", "started"),
      ("inclusion_proof_check", expected_check_state),
  ]
  (finished,) = _of_type(events, "device_finished")
  assert finished["status"] == expected_status
  # Results were collected in every case, so the directory is always reported.
  assert finished["results_dir"] == "/tmp/out/DEV1"
  assert events[-1]["summary"]["DEV1"]["status"] == expected_status
  if expected_status == "partial_error":
    assert finished["error"] == {"reason": "unexpected_error",
                                 "message": "RuntimeError: verifier crashed"}
  if expected_status == "partial_check_incomplete":
    # A False return means the check could not complete, not that APKs are
    # missing from the log; the message must not claim otherwise.
    assert finished["error"] == {
        "reason": "inclusion_proof_check_incomplete",
        "message": "Inclusion proof check could not complete."}


def test_main_events_inclusion_proof_progress_inside_step(
    serial_main_mocks, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
):
  m = serial_main_mocks
  m["AdbWrapper"].devices.return_value = [_make_mock_device("DEV1")]
  events_path = tmp_path / "events.jsonl"
  _set_argv(monkeypatch, "--events", str(events_path),
            "--perform_inclusion_proof_check", "--verifier_path=/v",
            "--no_prefetch")
  clock = _FakeMonotonic()
  real_emitter = automate_observation.EventEmitter

  def emitter_with_fake_clock(*args, **kwargs):
    return real_emitter(*args, monotonic=clock, **kwargs)

  def fake_check(*args, progress, **kwargs):
    for done in range(5):
      progress(done, 4)
      clock.now += 1.5  # 1.5 s per split: every other one is reported
    return True

  with mock.patch("automate_observation.os.path.isfile", return_value=True), \
       mock.patch("automate_observation.EventEmitter",
                  side_effect=emitter_with_fake_clock), \
       mock.patch("inclusion_proof_check.perform_inclusion_proof_check",
                  side_effect=fake_check):
    automate_observation.main()

  events = _read_events(events_path)
  check = [i for i, e in enumerate(events)
           if e.get("step") == "inclusion_proof_check"]
  started, finished = check[0], check[-1]
  assert events[started]["type"] == "step"
  assert events[started]["state"] == "started"
  progress = events[started + 1:finished]
  assert [(e["type"], e["step"], e["device"], e["done"], e["total"])
          for e in progress] == [
              ("step_progress", "inclusion_proof_check", "DEV1", 0, 4),
              ("step_progress", "inclusion_proof_check", "DEV1", 2, 4),
              ("step_progress", "inclusion_proof_check", "DEV1", 4, 4),
          ]
  assert events[finished]["state"] == "finished"
  # No progress events outside the step.
  assert len(_of_type(events, "step_progress")) == 3


def test_main_events_check_preinstalled_only_missing_file(
    serial_main_mocks, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
):
  m = serial_main_mocks
  m["AdbWrapper"].devices.return_value = [_make_mock_device("DEV1")]
  events_path = tmp_path / "events.jsonl"
  _set_argv(monkeypatch, "--events", str(events_path),
            "--perform_inclusion_proof_check", "--verifier_path=/v",
            "--check_preinstalled_only")
  with mock.patch("automate_observation.os.path.isfile", return_value=False):
    with pytest.raises(SystemExit):
      automate_observation.main()

  events = _read_events(events_path)
  assert _steps(events, "DEV1")[-2:] == [
      ("inclusion_proof_check", "started"),
      ("inclusion_proof_check", "failed"),
  ]
  (finished,) = _of_type(events, "device_finished")
  assert finished["status"] == "partial_check_incomplete"
  assert finished["error"]["reason"] == "inclusion_proof_check_incomplete"
  assert "preinstalled_packages.txt not found" in finished["error"]["message"]


def _fail_uninstall(m, stack):
  m["is_hubble_installed"].return_value = True
  stack.enter_context(mock.patch(
      "automate_observation.remove_previous_installation", return_value=False))


def _fail_install(m, stack):  # pylint: disable=unused-argument
  m["install_hubble"].return_value = False


def _fail_launch(m, stack):  # pylint: disable=unused-argument
  m["launch_hubble"].return_value = False


def _fail_wait(m, stack):  # pylint: disable=unused-argument
  m["wait_for_results"].return_value = None


def _fail_extract(m, stack):  # pylint: disable=unused-argument
  m["extract_results_and_apks"].side_effect = lambda *a, **kw: None


@pytest.mark.parametrize(
    "setup, failed_step, reason",
    [
        (_fail_uninstall, "uninstall_previous", "uninstall_failed"),
        (_fail_install, "install_hubble", "install_failed"),
        (_fail_launch, "launch_hubble", "launch_failed"),
        (_fail_wait, "wait_for_results", "no_results"),
        (_fail_extract, "extract_results", "extract_failed"),
    ],
    ids=["uninstall", "install", "launch", "wait", "extract"],
)
def test_main_events_device_error_reason_per_failed_step(
    serial_main_mocks, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    setup, failed_step, reason,
):
  m = serial_main_mocks
  m["AdbWrapper"].devices.return_value = [_make_mock_device("DEV1")]
  events_path = tmp_path / "events.jsonl"
  _set_argv(monkeypatch, "--events", str(events_path))
  with contextlib.ExitStack() as stack:
    setup(m, stack)
    with pytest.raises(SystemExit):
      automate_observation.main()

  events = _read_events(events_path)
  (step_failed,) = [e for e in events if e["type"] == "step"
                    and e["state"] == "failed"]
  assert step_failed["step"] == failed_step
  (finished,) = _of_type(events, "device_finished")
  assert finished["status"] == "failed"
  # The reason is a stable code; the message matches the failed step's.
  assert finished["error"] == {"reason": reason,
                               "message": step_failed["message"]}


@pytest.mark.parametrize(
    "mock_name, value, reason, failed_step",
    [
        ("supported_platform", False, "unsupported_platform", None),
        ("verify_hubble", False, "invalid_hubble_apk", "verify_hubble"),
        ("adb_installed", False, "adb_not_found", "check_adb"),
        ("AdbWrapper.start_server", False, "adb_server_failed",
         "start_adb_server"),
        ("AdbWrapper.devices", [], "no_devices", None),
        ("AdbWrapper.devices", None, "adb_devices_failed", "list_devices"),
    ],
)
def test_main_events_early_exits_keep_exit_0_and_report_reason(
    serial_main_mocks, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    mock_name, value, reason, failed_step,
):
  m = serial_main_mocks
  if "." in mock_name:
    owner, attr = mock_name.split(".")
    getattr(m[owner], attr).return_value = value
  else:
    m[mock_name].return_value = value
  events_path = tmp_path / "events.jsonl"
  _set_argv(monkeypatch, "--events", str(events_path))

  automate_observation.main()  # early exits still return exit code 0

  events = _read_events(events_path)
  assert events[0]["type"] == "run_started"
  run_finished = events[-1]
  assert run_finished["type"] == "run_finished"
  assert len(_of_type(events, "run_finished")) == 1
  assert run_finished["exit_code"] == 0
  assert run_finished["ok"] is False
  assert run_finished["summary"] == {}
  assert run_finished["error"]["reason"] == reason
  assert run_finished["error"]["message"]
  failed = [e["step"] for e in events
            if e["type"] == "step" and e["state"] == "failed"]
  assert failed == ([failed_step] if failed_step else [])
  assert _of_type(events, "devices") == []


def test_main_events_build_failure(
    serial_main_mocks, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
):
  events_path = tmp_path / "events.jsonl"
  monkeypatch.setattr(sys, "argv", ["automate_observation.py",
                                    "--events", str(events_path)])
  with mock.patch("automate_observation.ensure_android_sdk",
                  return_value=False):
    automate_observation.main()

  events = _read_events(events_path)
  assert _steps(events) == [("build_hubble", "started"),
                            ("build_hubble", "failed")]
  assert events[-1]["error"] == {
      "reason": "android_sdk_not_found",
      "message": "Failed to (re)build Hubble APK: Android SDK not found.",
  }
  serial_main_mocks["verify_hubble"].assert_not_called()


def test_main_events_unexpected_exception_reports_and_reraises(
    serial_main_mocks, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
):
  m = serial_main_mocks
  m["AdbWrapper"].devices.side_effect = ValueError("bad adb output")
  events_path = tmp_path / "events.jsonl"
  _set_argv(monkeypatch, "--events", str(events_path))

  with pytest.raises(ValueError):
    automate_observation.main()

  events = _read_events(events_path)
  assert _steps(events)[-1] == ("list_devices", "failed")
  assert events[-1]["type"] == "run_finished"
  assert events[-1]["exit_code"] == 1
  assert events[-1]["error"] == {"reason": "unexpected_error",
                                 "message": "ValueError: bad adb output"}


@pytest.mark.parametrize(
    "interrupt_at, expected_status",
    [
        ("wait_for_results", "failed"),
        # After results are collected: must not be reported as success.
        ("prefetch", "partial_error"),
        ("check", "partial_error"),
    ],
)
def test_main_events_keyboard_interrupt_during_device(
    serial_main_mocks, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    interrupt_at, expected_status,
):
  m = serial_main_mocks
  m["AdbWrapper"].devices.return_value = [_make_mock_device("DEV1")]
  events_path = tmp_path / "events.jsonl"
  _set_argv(monkeypatch, "--events", str(events_path),
            "--perform_inclusion_proof_check", "--verifier_path=/v")
  if interrupt_at == "wait_for_results":
    m["wait_for_results"].side_effect = KeyboardInterrupt
  prefetch = mock.patch(
      "inclusion_proof_check.prefetch_log_entries",
      side_effect=KeyboardInterrupt if interrupt_at == "prefetch" else None,
      return_value=True)
  check = mock.patch(
      "inclusion_proof_check.perform_inclusion_proof_check",
      side_effect=KeyboardInterrupt if interrupt_at == "check" else None,
      return_value=True)

  with mock.patch("automate_observation.os.path.isfile", return_value=True), \
       prefetch, check:
    with pytest.raises(KeyboardInterrupt):
      automate_observation.main()

  events = _read_events(events_path)
  (finished,) = _of_type(events, "device_finished")
  assert finished["status"] == expected_status
  assert finished["error"] == {"reason": "interrupted",
                               "message": "Interrupted."}
  if expected_status == "partial_error":
    assert finished["results_dir"] == "/tmp/out/DEV1"
  assert events[-1]["type"] == "run_finished"
  assert events[-1]["exit_code"] == 130
  assert events[-1]["error"]["reason"] == "interrupted"


def _two_devices_interrupted_on_second(m, exc):
  """DEV1 completes; DEV2 raises exc while waiting for Hubble's results."""
  m["AdbWrapper"].devices.return_value = [
      _make_mock_device("DEV1"), _make_mock_device("DEV2")]
  m["wait_for_results"].side_effect = [
      "/sdcard/hubble/results", exc]


def test_main_events_interrupt_reports_partial_summary(
    serial_main_mocks, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
):
  """Devices that finished before Ctrl-C stay in run_finished.summary."""
  m = serial_main_mocks
  _two_devices_interrupted_on_second(m, KeyboardInterrupt)
  events_path = tmp_path / "events.jsonl"
  _set_argv(monkeypatch, "--events", str(events_path),
            "-s", "GONE", "-s", "DEV1", "-s", "DEV2")

  with pytest.raises(KeyboardInterrupt):
    automate_observation.main()

  run_finished = _read_events(events_path)[-1]
  assert run_finished["error"]["reason"] == "interrupted"
  assert run_finished["summary"] == {
      "GONE": {"status": "failed"},
      "DEV1": {"status": "success", "results_dir": "/tmp/out/DEV1"},
      "DEV2": {"status": "failed"},
  }


def test_main_events_unexpected_error_after_devices_reports_partial_summary(
    serial_main_mocks, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
):
  m = serial_main_mocks
  m["AdbWrapper"].devices.return_value = [_make_mock_device("DEV1")]

  def _info(msg, *args):
    if msg.startswith("SUCCESS!"):  # fail while printing the log summary
      raise RuntimeError("logging broke")
  m["logger"].info.side_effect = _info
  events_path = tmp_path / "events.jsonl"
  _set_argv(monkeypatch, "--events", str(events_path))

  with pytest.raises(RuntimeError):
    automate_observation.main()

  run_finished = _read_events(events_path)[-1]
  assert run_finished["error"]["reason"] == "unexpected_error"
  assert run_finished["summary"] == {
      "DEV1": {"status": "success", "results_dir": "/tmp/out/DEV1"}}


def test_finish_run_defaults_to_recorded_devices_and_explicit_summary_wins():
  stream = io.StringIO()
  emitter = _emitter(stream)
  emitter.device_finished("A", "success", results_dir="/r/A")
  emitter.device_finished("B", "failed",
                          error={"reason": "unexpected_error",
                                 "message": "boom"})
  emitter.finish_run(1)
  events = _parse(stream)
  assert events[0] == {"v": 1, "ts": "2026-01-02T03:04:05.678Z",
                       "type": "device_finished", "device": "A",
                       "status": "success", "results_dir": "/r/A"}
  assert events[1]["error"] == {"reason": "unexpected_error",
                                "message": "boom"}
  assert events[-1]["summary"] == {"A": {"status": "success",
                                         "results_dir": "/r/A"},
                                   "B": {"status": "failed"}}

  stream = io.StringIO()
  emitter = _emitter(stream)
  emitter.device_finished("A", "success")
  emitter.finish_run(0, summary={"X": {"status": "success"}})
  assert _parse(stream)[-1]["summary"] == {"X": {"status": "success"}}


def test_main_sigterm_handler_only_installed_with_events(
    serial_main_mocks, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
):
  """Without --events SIGTERM is untouched; with it, restored afterwards."""
  m = serial_main_mocks
  m["AdbWrapper"].devices.return_value = [_make_mock_device("DEV1")]
  seen = []

  def _wait(*unused_args):
    seen.append(signal.getsignal(signal.SIGTERM))
    return "/sdcard/hubble/results"
  m["wait_for_results"].side_effect = _wait
  before = signal.getsignal(signal.SIGTERM)

  _set_argv(monkeypatch)
  automate_observation.main()
  _set_argv(monkeypatch, "--events", str(tmp_path / "events.jsonl"))
  automate_observation.main()

  assert seen == [before, termination.raise_terminated]
  assert signal.getsignal(signal.SIGTERM) == before


def test_main_events_terminated_in_process(
    serial_main_mocks, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
):
  """Terminated -> run_finished{terminated}, then die by SIGTERM (patched)."""
  m = serial_main_mocks
  _two_devices_interrupted_on_second(m, termination.Terminated())
  events_path = tmp_path / "events.jsonl"
  _set_argv(monkeypatch, "--events", str(events_path))
  before = signal.getsignal(signal.SIGTERM)

  with mock.patch("termination.die_by_sigterm") as die:
    automate_observation.main()
  die.assert_called_once_with(mock.ANY)
  assert signal.getsignal(signal.SIGTERM) == before

  events = _read_events(events_path)
  finished = {e["device"]: e for e in _of_type(events, "device_finished")}
  assert finished["DEV2"]["status"] == "failed"
  assert finished["DEV2"]["error"] == {"reason": "terminated",
                                       "message": "Terminated."}
  run_finished = events[-1]
  assert run_finished["type"] == "run_finished"
  assert run_finished["exit_code"] == 143
  assert run_finished["ok"] is False
  assert run_finished["error"] == {"reason": "terminated",
                                   "message": "Terminated by SIGTERM."}
  assert run_finished["summary"] == {
      "DEV1": {"status": "success", "results_dir": "/tmp/out/DEV1"},
      "DEV2": {"status": "failed"},
  }


_SIGTERM_DRIVER = textwrap.dedent("""
    import sys, time
    from unittest import mock
    sys.path.insert(0, {script_dir!r})
    import automate_observation as ao

    def dev(serial):
      d = mock.Mock(); d.serial_number = serial; d.unauthorized = False
      return d

    waits = iter(["/sdcard/hubble/results", None])
    def wait_for_results(*unused):
      result = next(waits)
      if result is None:
        time.sleep(60)  # DEV2 blocks here until the test sends SIGTERM
      return result

    patches = dict(
        supported_platform=True, verify_hubble=True, adb_installed=True,
        is_hubble_installed=False, is_xiaomi_phone=False, install_hubble=True,
        clear_logcat=None, launch_hubble=True, extract_selinux_policies=None)
    for name, value in patches.items():
      mock.patch.object(ao, name, return_value=value).start()
    adb = mock.patch.object(ao, "AdbWrapper").start()
    adb.start_server.return_value = True
    adb.devices.return_value = [dev("DEV1"), dev("DEV2")]
    mock.patch.object(ao, "wait_for_results",
                      side_effect=wait_for_results).start()
    mock.patch.object(ao, "extract_results_and_apks",
                      return_value="/tmp/out/DEV1").start()
    sys.argv = ["automate_observation.py", "-H", "x.apk",
                "--events", {events_path!r}]
    ao.main()
""")


def test_events_sigterm_in_real_process(tmp_path: Path):
  """A real SIGTERM mid-run: run_finished is written, exit status is -SIGTERM."""
  events_path = tmp_path / "events.jsonl"
  driver = tmp_path / "driver.py"
  driver.write_text(_SIGTERM_DRIVER.format(script_dir=SCRIPT_DIR,
                                           events_path=str(events_path)))
  proc = subprocess.Popen([sys.executable, str(driver)],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True)
  try:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
      text = events_path.read_text() if events_path.exists() else ""
      if '"step": "wait_for_results", "state": "started", "device": "DEV2"' in text:
        break
      if proc.poll() is not None:
        pytest.fail("driver exited early: " + proc.stderr.read())
      time.sleep(0.05)
    else:
      pytest.fail("DEV2 never reached wait_for_results")
    proc.send_signal(signal.SIGTERM)
    _, stderr = proc.communicate(timeout=30)
  finally:
    if proc.poll() is None:
      proc.kill()

  assert proc.returncode == -signal.SIGTERM, stderr
  events = _read_events(events_path)
  assert _steps(events, "DEV2")[-1] == ("wait_for_results", "failed")
  finished = {e["device"]: e for e in _of_type(events, "device_finished")}
  assert finished["DEV2"]["error"] == {"reason": "terminated",
                                       "message": "Terminated."}
  run_finished = events[-1]
  assert run_finished["type"] == "run_finished"
  assert run_finished["exit_code"] == 143
  assert run_finished["error"]["reason"] == "terminated"
  assert run_finished["summary"] == {
      "DEV1": {"status": "success", "results_dir": "/tmp/out/DEV1"},
      "DEV2": {"status": "failed"},
  }
  assert "Terminated by SIGTERM." in stderr


def test_main_events_unopenable_path_exits_1(
    serial_main_mocks, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
):
  bad_path = tmp_path / "no" / "such" / "dir" / "events.jsonl"
  _set_argv(monkeypatch, "--events", str(bad_path))
  with pytest.raises(SystemExit) as exc_info:
    automate_observation.main()
  assert exc_info.value.code == 1
  serial_main_mocks["supported_platform"].assert_not_called()


def test_main_without_events_writes_nothing(
    serial_main_mocks, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
):
  serial_main_mocks["AdbWrapper"].devices.return_value = [
      _make_mock_device("DEV1")]
  monkeypatch.chdir(tmp_path)
  _set_argv(monkeypatch)
  automate_observation.main()
  assert list(tmp_path.iterdir()) == []


# --- --events - (stdout) in a real process -----------------------------------------


def test_events_to_stdout_end_to_end_is_pure_json(tmp_path: Path):
  """A real run that stops early: stdout must carry only JSON Lines."""
  not_an_apk = tmp_path / "hubble.txt"
  not_an_apk.write_text("")
  proc = subprocess.run(
      [sys.executable, os.path.join(SCRIPT_DIR, "automate_observation.py"),
       "-H", str(not_an_apk), "--events", "-"],
      capture_output=True, text=True, timeout=60, check=False)

  assert proc.returncode == 0, proc.stderr
  events = [json.loads(line) for line in proc.stdout.splitlines()]
  assert [e["type"] for e in events] == [
      "run_started", "step", "step", "run_finished"]
  assert _steps(events) == [("verify_hubble", "started"),
                            ("verify_hubble", "failed")]
  assert events[-1]["error"]["reason"] == "invalid_hubble_apk"
  # Human-readable logging still goes to stderr.
  assert ".apk extension" in proc.stderr


def test_open_event_stream_dash_moves_other_stdout_writes_to_stderr():
  """print(), input() prompts and child processes must not pollute stdout."""
  code = textwrap.dedent("""
      import subprocess, sys
      sys.path.insert(0, {script_dir!r})
      import automate_observation as ao
      emitter = ao.EventEmitter(ao.open_event_stream("-"))
      print("noise from print")
      subprocess.run([sys.executable, "-c", "print('noise from child')"])
      emitter.emit("hello")
      emitter.close()
  """).format(script_dir=SCRIPT_DIR)
  proc = subprocess.run([sys.executable, "-c", code], capture_output=True,
                        text=True, timeout=60, check=False)

  assert proc.returncode == 0, proc.stderr
  (line,) = proc.stdout.splitlines()
  assert json.loads(line)["type"] == "hello"
  assert "noise from print" in proc.stderr
  assert "noise from child" in proc.stderr


# --- Manual-intervention prompts ------------------------------------------------


def test_prompt_is_always_followed_by_prompt_resolved():
  stream = io.StringIO()
  emitter = _emitter(stream)
  with emitter.prompt("DEV1", "some_kind", "Do something.",
                      expects_input=True):
    pass
  with pytest.raises(KeyboardInterrupt):
    with emitter.prompt(None, "other_kind", "Wait.", expects_input=False):
      raise KeyboardInterrupt()
  assert _parse(stream) == [
      {"v": 1, "ts": "2026-01-02T03:04:05.678Z", "type": "prompt",
       "device": "DEV1", "kind": "some_kind", "message": "Do something.",
       "expects_input": True},
      {"v": 1, "ts": "2026-01-02T03:04:05.678Z", "type": "prompt_resolved",
       "device": "DEV1", "kind": "some_kind", "outcome": "done"},
      {"v": 1, "ts": "2026-01-02T03:04:05.678Z", "type": "prompt",
       "kind": "other_kind", "message": "Wait.", "expects_input": False},
      {"v": 1, "ts": "2026-01-02T03:04:05.678Z", "type": "prompt_resolved",
       "kind": "other_kind", "outcome": "interrupted"},
  ]


@pytest.mark.parametrize(
    "body, expected_outcome",
    [
        (lambda p: None, "done"),
        (lambda p: setattr(p, "outcome", "failed"), "failed"),
        (lambda p: setattr(p, "outcome", "stdin_closed"), "stdin_closed"),
    ],
    ids=["default", "failed", "stdin_closed"],
)
def test_prompt_outcome_set_by_body(body, expected_outcome):
  stream = io.StringIO()
  with _emitter(stream).prompt("DEV1", "k", "m", expects_input=True) as p:
    body(p)
  assert _parse(stream)[-1]["outcome"] == expected_outcome


@pytest.mark.parametrize(
    "exc, expected_outcome",
    [
        (KeyboardInterrupt(), "interrupted"),
        (termination.Terminated(), "terminated"),
        (RuntimeError("boom"), "unexpected_error"),
    ],
    ids=["ctrl_c", "sigterm", "exception"],
)
def test_prompt_outcome_from_exception_overrides_body(exc, expected_outcome):
  stream = io.StringIO()
  with pytest.raises(type(exc)):
    with _emitter(stream).prompt("DEV1", "k", "m", expects_input=True) as p:
      p.outcome = "failed"
      raise exc
  assert _parse(stream)[-1] == {
      "v": 1, "ts": "2026-01-02T03:04:05.678Z", "type": "prompt_resolved",
      "device": "DEV1", "kind": "k", "outcome": expected_outcome}


def test_prompt_without_stream_is_a_noop():
  with EventEmitter().prompt("DEV1", "k", "m", expects_input=True):
    pass


@pytest.fixture
def xiaomi_mocks(serial_main_mocks):
  m = serial_main_mocks
  m["AdbWrapper"].devices.return_value = [_make_mock_device("DEV1")]
  m["is_xiaomi_phone"].return_value = True
  with mock.patch("automate_observation.adb_push_hubble"), \
       mock.patch("automate_observation.launch_xiaomi_file_explorer",
                  return_value=True):
    yield m


def test_main_events_xiaomi_manual_install_prompt(
    xiaomi_mocks, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
):
  m = xiaomi_mocks
  # Not installed beforehand; then still missing after the first Enter, and
  # installed after the second.
  m["is_hubble_installed"].side_effect = [False, False, False, True]
  stdin = io.StringIO("\n\n")
  monkeypatch.setattr(sys, "stdin", stdin)
  events_path = tmp_path / "events.jsonl"
  _set_argv(monkeypatch, "--events", str(events_path))
  extract = m["extract_results_and_apks"].side_effect
  emitter_enabled_at_extract = []

  def _extract(*args, **kwargs):
    emitter_enabled_at_extract.append(kwargs["events"].enabled)
    return extract(*args, **kwargs)

  m["extract_results_and_apks"].side_effect = _extract

  automate_observation.main()

  assert stdin.read() == ""  # both newlines consumed by the real input()
  events = _read_events(events_path)
  install = [e for e in events if e["type"] in ("prompt", "prompt_resolved")
             or (e["type"] == "step" and e["step"] == "install_hubble")]
  assert [(e["type"], e.get("state")) for e in install] == [
      ("step", "started"), ("prompt", None), ("prompt_resolved", None),
      ("step", "finished")]
  prompt = install[1]
  assert prompt["device"] == "DEV1"
  assert prompt["kind"] == "xiaomi_manual_install"
  assert prompt["expects_input"] is True
  assert "press Enter" in prompt["message"]
  assert (install[2]["device"], install[2]["kind"], install[2]["outcome"]) == (
      "DEV1", "xiaomi_manual_install", "done")
  (finished,) = _of_type(events, "device_finished")
  assert finished["status"] == "success"
  # The live emitter is also handed down for the adb backup prompt.
  assert emitter_enabled_at_extract == [True]


def test_main_events_xiaomi_already_installed_after_push_has_no_prompt(
    xiaomi_mocks, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
):
  m = xiaomi_mocks
  m["is_hubble_installed"].side_effect = [False, True]
  events_path = tmp_path / "events.jsonl"
  _set_argv(monkeypatch, "--events", str(events_path))
  with mock.patch("builtins.input") as fake_input:
    automate_observation.main()
  fake_input.assert_not_called()
  assert not _of_type(_read_events(events_path), "prompt")


@pytest.mark.parametrize("with_events", [True, False])
def test_main_xiaomi_stdin_closed_fails_device_and_stops_waiting(
    xiaomi_mocks, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    with_events,
):
  m = xiaomi_mocks
  m["is_hubble_installed"].return_value = False  # never installed
  monkeypatch.setattr(sys, "stdin", io.StringIO(""))  # EOF on first read
  events_path = tmp_path / "events.jsonl"
  _set_argv(monkeypatch,
            *(["--events", str(events_path)] if with_events else []))

  with pytest.raises(SystemExit) as exc_info:
    automate_observation.main()

  assert exc_info.value.code == 1
  m["launch_hubble"].assert_not_called()
  # Reported as a clear error, not as an unexpected exception.
  m["logger"].exception.assert_not_called()
  assert any("Standard input was closed" in c.args[0]
             for c in m["logger"].error.call_args_list)
  if not with_events:
    assert not events_path.exists()
    return
  events = _read_events(events_path)
  assert [(e["type"], e.get("outcome")) for e in events
          if e["type"] in ("prompt", "prompt_resolved")] == [
              ("prompt", None), ("prompt_resolved", "stdin_closed")]
  assert _steps(events, "DEV1") == [
      ("install_hubble", "started"), ("install_hubble", "failed")]
  (finished,) = _of_type(events, "device_finished")
  assert finished["status"] == "failed"
  assert finished["error"]["reason"] == "stdin_closed"
  assert events[-1]["summary"] == {"DEV1": {"status": "failed"}}


def test_adb_backup_confirmation_is_reported_as_prompt(tmp_path: Path):
  stream = io.StringIO()
  emitter = _emitter(stream)
  mock_adb = mock.Mock()
  mock_adb.device_serial_number = "DEV1"
  mock_adb.pull.return_value = False  # forces the adb backup fallback
  events_during_backup = []

  def fake_backup(ab_path, pkg_name):  # pylint: disable=unused-argument
    events_during_backup.extend(_parse(stream))
    return False

  mock_adb.backup.side_effect = fake_backup

  assert automate_observation.classify_dir_using_build_fingerprint(
      mock_adb, "/sdcard/hubble/results", str(tmp_path / "results"),
      extract_apks=False, logger=mock.Mock(), tmp_dir=str(tmp_path),
      events=emitter) is None

  # The prompt is open while `adb backup` blocks, and closed afterwards even
  # though the backup failed.
  assert [e["type"] for e in events_during_backup] == ["prompt"]
  assert events_during_backup[0]["device"] == "DEV1"
  assert events_during_backup[0]["kind"] == "adb_backup_confirm"
  assert events_during_backup[0]["expects_input"] is False
  assert [(e["type"], e["kind"], e.get("outcome"))
          for e in _parse(stream)] == [
              ("prompt", "adb_backup_confirm", None),
              ("prompt_resolved", "adb_backup_confirm", "failed")]


if __name__ == "__main__":
  sys.exit(pytest.main([__file__]))
