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
import signal
import subprocess
import sys
import textwrap
import threading
import time
from unittest import mock
import pytest

# Ensure uraniborg/scripts/python is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import inclusion_proof_check

_SCRIPT = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "inclusion_proof_check.py"))
_OK = (0, "OK. inclusion check success!", "")
_NOT_FOUND = (1, "", "inclusion check failed")


@pytest.fixture
def logger() -> logging.Logger:
  log = logging.getLogger("test_logger")
  log.setLevel(logging.DEBUG)
  return log


_UNSUPPORTED_BATCH = (2, [], "flag provided but not defined: -payloads_path\n")


def _is_batch(cmd) -> bool:
  return any(arg.startswith("--payloads_path=") for arg in cmd)


class _FakeProcess:
  """subprocess.Popen stand-in for one verifier run."""

  def __init__(self, cmd, result_for, batch_for, **kwargs):
    self.cmd = cmd
    self.returncode = None
    self.killed = False
    self._result_for = result_for
    if _is_batch(cmd):
      self._batch_returncode, lines, stderr = batch_for(cmd)
      self.stdout = iter(lines)
      kwargs["stderr"].write(stderr)

  def __enter__(self):
    return self

  def __exit__(self, *exc_info):
    return False

  def communicate(self, input=None, timeout=None):  # pylint: disable=redefined-builtin
    self.returncode, stdout, stderr = self._result_for(self.cmd)
    return stdout, stderr

  def poll(self):
    return self.returncode

  def wait(self):
    if self.returncode is None:
      self.returncode = self._batch_returncode
    return self.returncode

  def kill(self):
    self.killed = True
    self.returncode = -signal.SIGKILL


def _fake_popen(result_for, batch_for=lambda cmd: _UNSUPPORTED_BATCH):
  """Returns a subprocess.Popen stand-in for verifier runs.

  Args:
    result_for: for a single-payload run, called with the command when the
                process is waited for (in communicate(), like a real
                process's work); returns (returncode, stdout, stderr).
    batch_for: for a batch run (--payloads_path), called with the command when
               the process starts; returns (returncode, stdout lines, stderr).
               By default, the verifier does not support batch mode.
  """
  def factory(cmd, **kwargs):
    return _FakeProcess(cmd, result_for, batch_for, **kwargs)
  return mock.Mock(side_effect=factory)


def _split_cmds(popen) -> list:
  """The single-payload verifier commands a fake Popen was called with."""
  return [c.args[0] for c in popen.call_args_list if not _is_batch(c.args[0])]


def _batch_cmds(popen) -> list:
  return [c.args[0] for c in popen.call_args_list if _is_batch(c.args[0])]


def _batch_payloads(cmd) -> list:
  """Reads the payloads of a batch verifier command."""
  prefix = "--payloads_path="
  path = next(arg[len(prefix):] for arg in cmd if arg.startswith(prefix))
  return [json.loads(line)["payload"]
          for line in Path(path).read_text().splitlines()]


def _batch_result(index, verified, **extra) -> str:
  return json.dumps(dict(index=index, verified=verified, **extra)) + "\n"


def _payload_of(cmd) -> str:
  """Reads the payload file a verifier command refers to."""
  prefix = "--payload_path="
  path = next(arg[len(prefix):] for arg in cmd if arg.startswith(prefix))
  return Path(path).read_text()


def _write_packages(path: Path, packages, key="packages") -> Path:
  path.write_text(json.dumps({key: packages}))
  return path


def _write_fake_verifier(tmp_path: Path, body: str) -> Path:
  """Writes an executable Python script that stands in for the verifier."""
  path = tmp_path / "fake_verifier"
  path.write_text("#!{}\n".format(sys.executable) + textwrap.dedent(body))
  path.chmod(0o755)
  return path


def _wait_for(predicate, timeout=10.0):
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    if predicate():
      return True
    time.sleep(0.05)
  return False


def _process_exists(pid: int) -> bool:
  try:
    os.kill(pid, 0)
  except ProcessLookupError:
    return False
  return True


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


def test_run_verifier_with_cache_dir(tmp_path: Path, logger: logging.Logger):
  payload_file = tmp_path / "payload.txt"
  payload_file.write_text("hash\nSHA256(APK)\ncom.example\n1\n")

  with mock.patch("subprocess.Popen", _fake_popen(lambda cmd: _OK)) as popen:
    verified = inclusion_proof_check.run_verifier(
        "/path/to/verifier",
        str(payload_file),
        logger,
        cache_dir="/custom/cache",
    )

  assert verified is True
  popen.assert_called_once_with(
      [
          "/path/to/verifier",
          f"--payload_path={payload_file}",
          "--log_type=google_1p_apk",
          "--cache_dir=/custom/cache",
      ],
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      text=True,
  )


def test_run_verifier_names_split_in_log_lines(
    tmp_path: Path, logger: logging.Logger, caplog: pytest.LogCaptureFixture
):
  payload_file = tmp_path / "payload.txt"
  payload_file.write_text("hash\nSHA256(APK)\ncom.example\n1\n")

  with caplog.at_level(logging.DEBUG, logger=logger.name):
    with mock.patch("subprocess.Popen", _fake_popen(lambda cmd: _NOT_FOUND)):
      verified = inclusion_proof_check.run_verifier(
          "/path/to/verifier", str(payload_file), logger,
          label="com.example [config.en]")

  assert verified is False
  assert caplog.records
  for record in caplog.records:
    assert record.getMessage().startswith("com.example [config.en]: ")


def test_run_verifier_file_not_found_is_failure(
    tmp_path: Path, logger: logging.Logger
):
  payload_file = tmp_path / "payload.txt"
  payload_file.write_text("payload")

  with mock.patch("subprocess.Popen", side_effect=FileNotFoundError()):
    assert inclusion_proof_check.run_verifier(
        "/bad/verifier", str(payload_file), logger) is False


@mock.patch("subprocess.run")
def test_perform_inclusion_proof_check_with_prefetch(
    mock_run: mock.MagicMock, tmp_path: Path, logger: logging.Logger
):
  mock_run.return_value = mock.Mock(returncode=0, stdout="prefetched", stderr="")

  packages_file = _write_packages(tmp_path / "packages.txt", [{
      "name": "com.google.android.gm",
      "versionCode": 123,
      "splits": [{"hash": "abc123hash"}],
  }])

  with mock.patch("subprocess.Popen", _fake_popen(lambda cmd: _OK)) as popen:
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
  mock_run.assert_called_once()
  prefetch_cmd = mock_run.call_args_list[0][0][0]
  assert "--fetch_entries" in prefetch_cmd
  assert "--concurrency=32" in prefetch_cmd
  assert "--cache_dir=/tmp/cache" in prefetch_cmd
  assert mock_run.call_args_list[0].kwargs["timeout"] == 45

  assert len(_split_cmds(popen)) == 1
  verify_cmd = _split_cmds(popen)[0]
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
  packages_file = _write_packages(tmp_path / "packages.txt", [{
      "name": "com.google.android.gm",
      "versionCode": 123,
      "splits": [{"hash": "abc123hash"}],
  }])

  with mock.patch("subprocess.Popen", _fake_popen(lambda cmd: _OK)) as popen:
    success = inclusion_proof_check.perform_inclusion_proof_check(
        "/path/to/verifier",
        str(packages_file),
        logger,
        cache_dir="/tmp/cache",
        prefetch=False,
    )

  assert success is True
  mock_run.assert_not_called()
  assert len(_split_cmds(popen)) == 1
  verify_cmd = _split_cmds(popen)[0]
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
  mock_run.return_value = mock.Mock(
      returncode=1, stdout="", stderr="prefetch network timeout")

  packages_file = _write_packages(tmp_path / "packages.txt", [{
      "name": "com.google.android.gm",
      "versionCode": 123,
      "splits": [{"hash": "abc123hash"}],
  }])

  with mock.patch("subprocess.Popen", _fake_popen(lambda cmd: _OK)) as popen:
    success = inclusion_proof_check.perform_inclusion_proof_check(
        "/path/to/verifier",
        str(packages_file),
        logger,
        prefetch=True,
    )

  assert success is True
  mock_run.assert_called_once()
  assert len(_split_cmds(popen)) == 1

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
  mock_run.return_value = mock.Mock(returncode=0, stdout="prefetched", stderr="")

  # Also create an existing full-run output file to verify it is NOT overwritten
  existing_full_output = tmp_path / inclusion_proof_check.OUTPUT_FILENAME
  existing_full_output.write_text(json.dumps({
      "source": "packages.txt",
      "totalPackages": 401,
      "packages": [],
  }))

  preinstalled_file = tmp_path / "preinstalled_packages.txt"
  preinstalled_file.write_text(json.dumps({
      "version": "2.2.0",
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

  with mock.patch("subprocess.Popen", _fake_popen(lambda cmd: _OK)):
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


def _many_packages():
  """Packages with several splits, in a deliberately non-sorted order."""
  return [
      {"name": "com.z.last", "versionCode": 3, "splits": [
          {"name": "base", "hash": "z0"},
          {"name": "config.en", "hash": "z1-ok"},
          {"name": "config.xxhdpi", "hash": "z2"},
      ]},
      {"name": "com.a.first", "versionCode": 1, "hash": "a-ok"},
      {"name": "com.m.middle", "versionCode": 2, "splits": [
          {"hash": "m0-ok"},
          {"hash": "m1"},
      ]},
      {"name": "com.no.hash", "versionCode": 4},
  ]


def test_perform_inclusion_proof_check_one_at_a_time_results_and_order(
    tmp_path: Path, logger: logging.Logger
):
  packages_file = _write_packages(tmp_path / "packages.txt", _many_packages())

  def result_for(cmd):
    split_hash = _payload_of(cmd).split("\n")[0]
    # Finish in a scrambled order, so results complete out of order.
    time.sleep((hash(split_hash) % 5) / 500)
    return _OK if split_hash.endswith("-ok") else _NOT_FOUND

  with mock.patch("subprocess.Popen", _fake_popen(result_for)) as popen:
    success = inclusion_proof_check.perform_inclusion_proof_check(
        "/path/to/verifier", str(packages_file), logger, prefetch=False)

  assert success is True
  assert len(_split_cmds(popen)) == 6
  result_json = json.loads(
      (tmp_path / inclusion_proof_check.OUTPUT_FILENAME).read_text())
  assert [
      (p["name"], [(s["hash"], s["inclusion_proof_verified"])
                   for s in p["splits"]])
      for p in result_json["packages"]
  ] == [
      ("com.z.last", [("z0", False), ("z1-ok", True), ("z2", False)]),
      ("com.a.first", [("a-ok", True)]),
      ("com.m.middle", [("m0-ok", True), ("m1", False)]),
  ]


def test_perform_inclusion_proof_check_reports_progress(
    tmp_path: Path, logger: logging.Logger
):
  packages_file = _write_packages(tmp_path / "packages.txt", _many_packages())
  calls = []
  threads = set()

  def progress(done, total):
    calls.append((done, total))
    threads.add(threading.get_ident())

  with mock.patch("subprocess.Popen", _fake_popen(lambda cmd: _OK)):
    assert inclusion_proof_check.perform_inclusion_proof_check(
        "/path/to/verifier", str(packages_file), logger, prefetch=False, progress=progress)

  # Skipped packages (com.no.hash) are not counted.
  assert calls == [(done, 6) for done in range(7)]
  assert threads == {threading.get_ident()}  # Always the calling thread.


@mock.patch("subprocess.run")
def test_perform_inclusion_proof_check_progress_starts_after_prefetch(
    mock_run: mock.MagicMock, tmp_path: Path, logger: logging.Logger
):
  order = []
  mock_run.side_effect = lambda *a, **k: order.append("prefetch") or mock.Mock(
      returncode=0)
  packages_file = _write_packages(tmp_path / "packages.txt", _many_packages())

  with mock.patch("subprocess.Popen", _fake_popen(lambda cmd: _OK)):
    inclusion_proof_check.perform_inclusion_proof_check(
        "/path/to/verifier", str(packages_file), logger, prefetch=True,
        progress=lambda done, total: order.append((done, total)))

  assert order[:2] == ["prefetch", (0, 6)]


def test_perform_inclusion_proof_check_progress_empty_and_invalid_input(
    tmp_path: Path, logger: logging.Logger
):
  calls = []
  empty = _write_packages(tmp_path / "packages.txt", [])
  assert inclusion_proof_check.perform_inclusion_proof_check(
      "/v", str(empty), logger, prefetch=False,
      progress=lambda *a: calls.append(a))
  assert calls == [(0, 0)]

  calls.clear()
  invalid = tmp_path / "bad" / "packages.txt"
  invalid.parent.mkdir()
  invalid.write_text("{not json")
  assert not inclusion_proof_check.perform_inclusion_proof_check(
      "/v", str(invalid), logger, prefetch=False,
      progress=lambda *a: calls.append(a))
  assert not inclusion_proof_check.perform_inclusion_proof_check(
      "/v", str(tmp_path / "missing.txt"), logger, prefetch=False,
      progress=lambda *a: calls.append(a))
  assert calls == []


def test_perform_inclusion_proof_check_gives_each_split_its_own_payload(
    tmp_path: Path, logger: logging.Logger
):
  packages_file = _write_packages(tmp_path / "packages.txt", _many_packages())
  seen = {}
  lock = threading.Lock()

  def result_for(cmd):
    path = next(a for a in cmd if a.startswith("--payload_path="))
    payload = _payload_of(cmd)
    time.sleep(0.02)
    # The file still holds this split's payload after other workers ran.
    assert _payload_of(cmd) == payload
    with lock:
      seen[path] = payload
    return _OK

  with mock.patch("subprocess.Popen", _fake_popen(result_for)):
    assert inclusion_proof_check.perform_inclusion_proof_check(
        "/path/to/verifier", str(packages_file), logger, prefetch=False)

  assert len(seen) == 6  # One temp file per split...
  assert sorted(seen.values()) == sorted([
      "z0\nSHA256(APK)\ncom.z.last\n3\n",
      "z1-ok\nSHA256(APK)\ncom.z.last\n3\n",
      "z2\nSHA256(APK)\ncom.z.last\n3\n",
      "a-ok\nSHA256(APK)\ncom.a.first\n1\n",
      "m0-ok\nSHA256(APK)\ncom.m.middle\n2\n",
      "m1\nSHA256(APK)\ncom.m.middle\n2\n",
  ])
  for path in seen:  # ...removed afterwards.
    assert not os.path.exists(path[len("--payload_path="):])


def test_perform_inclusion_proof_check_labels_name_package_and_split(
    tmp_path: Path, logger: logging.Logger, caplog: pytest.LogCaptureFixture
):
  packages_file = _write_packages(tmp_path / "packages.txt", _many_packages())

  with caplog.at_level(logging.DEBUG, logger=logger.name):
    with mock.patch("subprocess.Popen", _fake_popen(lambda cmd: _OK)):
      inclusion_proof_check.perform_inclusion_proof_check(
          "/path/to/verifier", str(packages_file), logger, prefetch=False)

  passed = sorted(
      r.getMessage()[:-len(": Verifier check passed.")]
      for r in caplog.records
      if r.getMessage().endswith(": Verifier check passed."))
  assert passed == [
      "com.a.first [base]",
      "com.m.middle [split 0]",
      "com.m.middle [split 1]",
      "com.z.last [base]",
      "com.z.last [config.en]",
      "com.z.last [config.xxhdpi]",
  ]


_HANGING_VERIFIER = """
    import os, sys, time
    if any(a.startswith("--payloads_path=") for a in sys.argv):
      # No batch mode: what Go's flag package does with an unknown flag.
      print("flag provided but not defined: -payloads_path", file=sys.stderr)
      sys.exit(2)
    pid_dir = os.environ["FAKE_VERIFIER_PID_DIR"]
    open(os.path.join(pid_dir, str(os.getpid())), "w").close()
    time.sleep(60)
"""

# Supports batch mode: reports the first payload, then hangs.
_HANGING_BATCH_VERIFIER = """
    import os, sys, time
    pid_dir = os.environ["FAKE_VERIFIER_PID_DIR"]
    print('{"index": 0, "verified": true}', flush=True)
    open(os.path.join(pid_dir, str(os.getpid())), "w").close()
    time.sleep(60)
"""


def test_interrupt_kills_running_verifier_and_starts_no_more(
    tmp_path: Path, logger: logging.Logger, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture
):
  pid_dir = tmp_path / "pids"
  pid_dir.mkdir()
  monkeypatch.setenv("FAKE_VERIFIER_PID_DIR", str(pid_dir))
  verifier = _write_fake_verifier(tmp_path, _HANGING_VERIFIER)
  packages_file = _write_packages(tmp_path / "packages.txt", [
      {"name": "com.example.{}".format(i), "versionCode": 1,
       "hash": "h{}".format(i)}
      for i in range(6)
  ])

  def interrupt_when_started():
    if _wait_for(lambda: os.listdir(pid_dir)):
      os.kill(os.getpid(), signal.SIGINT)

  threading.Thread(target=interrupt_when_started, daemon=True).start()
  started = time.monotonic()
  with pytest.raises(KeyboardInterrupt):
    inclusion_proof_check.perform_inclusion_proof_check(
        str(verifier), str(packages_file), logger, prefetch=False)

  assert time.monotonic() - started < 20
  pids = [int(name) for name in os.listdir(pid_dir)]
  # Pending splits were never started.
  assert len(pids) == 1
  for pid in pids:
    assert _wait_for(lambda: not _process_exists(pid), timeout=5)
  assert not (tmp_path / inclusion_proof_check.OUTPUT_FILENAME).exists()
  assert "Inclusion proof check interrupted after 0 of 6 split(s)." in [
      r.getMessage() for r in caplog.records]


@pytest.mark.parametrize("verifier_body", [
    _HANGING_VERIFIER, _HANGING_BATCH_VERIFIER],
                         ids=["one_at_a_time", "batch"])
def test_main_sigterm_kills_running_verifier(
    tmp_path: Path, verifier_body: str
):
  pid_dir = tmp_path / "pids"
  pid_dir.mkdir()
  verifier = _write_fake_verifier(tmp_path, verifier_body)
  packages_file = _write_packages(tmp_path / "packages.txt", [
      {"name": "com.example.{}".format(i), "versionCode": 1,
       "hash": "h{}".format(i)}
      for i in range(4)
  ])

  process = subprocess.Popen(
      [sys.executable, _SCRIPT, "--packages_file", str(packages_file),
       "--verifier_path", str(verifier), "--no_prefetch"],
      env=dict(os.environ, FAKE_VERIFIER_PID_DIR=str(pid_dir)),
      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
  try:
    assert _wait_for(lambda: os.listdir(pid_dir))
    time.sleep(0.2)  # Let the batch result be read, if any.
    process.send_signal(signal.SIGTERM)
    _, stderr = process.communicate(timeout=20)
  finally:
    if process.poll() is None:
      process.kill()

  assert process.returncode == -signal.SIGTERM
  assert "Terminated by SIGTERM." in stderr
  pids = [int(name) for name in os.listdir(pid_dir)]
  assert len(pids) == 1  # No second verifier was started.
  for pid in pids:
    assert _wait_for(lambda: not _process_exists(pid), timeout=5)
  assert not (tmp_path / inclusion_proof_check.OUTPUT_FILENAME).exists()


def test_interrupt_kills_batch_verifier(
    tmp_path: Path, logger: logging.Logger, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture
):
  pid_dir = tmp_path / "pids"
  pid_dir.mkdir()
  monkeypatch.setenv("FAKE_VERIFIER_PID_DIR", str(pid_dir))
  verifier = _write_fake_verifier(tmp_path, _HANGING_BATCH_VERIFIER)
  packages_file = _write_packages(tmp_path / "packages.txt", [
      {"name": "com.example.{}".format(i), "versionCode": 1,
       "hash": "h{}".format(i)}
      for i in range(3)
  ])
  calls = []

  def interrupt_when_started():
    if _wait_for(lambda: os.listdir(pid_dir) and len(calls) >= 2):
      os.kill(os.getpid(), signal.SIGINT)

  threading.Thread(target=interrupt_when_started, daemon=True).start()
  started = time.monotonic()
  with pytest.raises(KeyboardInterrupt):
    inclusion_proof_check.perform_inclusion_proof_check(
        str(verifier), str(packages_file), logger, prefetch=False,
        progress=lambda *a: calls.append(a))

  assert time.monotonic() - started < 20
  # The result printed before the interrupt was reported as it arrived.
  assert calls == [(0, 3), (1, 3)]
  pids = [int(name) for name in os.listdir(pid_dir)]
  assert len(pids) == 1  # No per-split verifiers were started.
  assert _wait_for(lambda: not _process_exists(pids[0]), timeout=5)
  assert "Inclusion proof check interrupted after 1 of 3 split(s)." in [
      r.getMessage() for r in caplog.records]


def _results_by_hash(tmp_path: Path) -> dict:
  result_json = json.loads(
      (tmp_path / inclusion_proof_check.OUTPUT_FILENAME).read_text())
  return {s["hash"]: s["inclusion_proof_verified"]
          for p in result_json["packages"] for s in p["splits"]}


_MANY_PACKAGES_RESULTS = {
    "z0": False, "z1-ok": True, "z2": False, "a-ok": True, "m0-ok": True,
    "m1": False,
}


def test_perform_inclusion_proof_check_batch_mode(
    tmp_path: Path, logger: logging.Logger
):
  packages_file = _write_packages(tmp_path / "packages.txt", _many_packages())
  seen = {}
  calls = []

  def batch_for(cmd):
    payloads = _batch_payloads(cmd)
    seen["payloads"] = payloads
    # Results arrive in any order.
    lines = [_batch_result(i, p.split("\n")[0].endswith("-ok"))
             for i, p in reversed(list(enumerate(payloads)))]
    return 0, lines, "INFO Verified payloads\n"

  with mock.patch("subprocess.Popen",
                  _fake_popen(lambda cmd: pytest.fail("per-split run"),
                              batch_for)) as popen:
    assert inclusion_proof_check.perform_inclusion_proof_check(
        "/path/to/verifier", str(packages_file), logger, prefetch=False,
        cache_dir="/tmp/cache", progress=lambda *a: calls.append(a))

  (cmd,) = _batch_cmds(popen)
  assert _split_cmds(popen) == []
  assert "--log_type=google_1p_apk" in cmd
  assert "--cache_dir=/tmp/cache" in cmd
  # Payloads in input order, same format as per-split payload files.
  assert seen["payloads"] == [
      "z0\nSHA256(APK)\ncom.z.last\n3\n",
      "z1-ok\nSHA256(APK)\ncom.z.last\n3\n",
      "z2\nSHA256(APK)\ncom.z.last\n3\n",
      "a-ok\nSHA256(APK)\ncom.a.first\n1\n",
      "m0-ok\nSHA256(APK)\ncom.m.middle\n2\n",
      "m1\nSHA256(APK)\ncom.m.middle\n2\n",
  ]
  payloads_path = next(a for a in cmd if a.startswith("--payloads_path="))
  assert not os.path.exists(payloads_path[len("--payloads_path="):])
  assert _results_by_hash(tmp_path) == _MANY_PACKAGES_RESULTS
  assert calls == [(done, 6) for done in range(7)]


def test_perform_inclusion_proof_check_falls_back_without_batch_mode(
    tmp_path: Path, logger: logging.Logger, caplog: pytest.LogCaptureFixture
):
  packages_file = _write_packages(tmp_path / "packages.txt", _many_packages())

  def result_for(cmd):
    return _OK if _payload_of(cmd).split("\n")[0].endswith("-ok") else _NOT_FOUND

  with caplog.at_level(logging.INFO, logger=logger.name):
    with mock.patch("subprocess.Popen", _fake_popen(result_for)) as popen:
      assert inclusion_proof_check.perform_inclusion_proof_check(
          "/path/to/verifier", str(packages_file), logger, prefetch=False)

  assert len(_batch_cmds(popen)) == 1
  assert len(_split_cmds(popen)) == 6
  assert _results_by_hash(tmp_path) == _MANY_PACKAGES_RESULTS
  messages = [r.getMessage() for r in caplog.records]
  # Slow, and fixed by rebuilding the verifier: worth a warning.
  assert ("Verifier does not support batch mode; verifying 6 split(s) one at "
          "a time, which is slow. Rebuild the verifier for faster checks."
          in [r.getMessage() for r in caplog.records
              if r.levelno == logging.WARNING])


@pytest.mark.parametrize("returncode", [0, 1])
def test_perform_inclusion_proof_check_batch_leftovers_verified_per_split(
    tmp_path: Path, logger: logging.Logger, caplog: pytest.LogCaptureFixture,
    returncode: int
):
  packages_file = _write_packages(tmp_path / "packages.txt", _many_packages())
  calls = []

  def batch_for(cmd):
    return returncode, [
        _batch_result(1, True),        # z1-ok
        "not json\n",
        _batch_result(1, False),       # Duplicate: ignored.
        _batch_result(99, True),       # Out of range: ignored.
        _batch_result(True, True),     # Not an index: ignored.
        json.dumps({"index": 2}) + "\n",  # No verdict: ignored.
        _batch_result(5, False, error="inclusion check error"),  # m1
        "\n",
    ], "verifier log\n"

  per_split = []
  lock = threading.Lock()

  def result_for(cmd):
    split_hash = _payload_of(cmd).split("\n")[0]
    with lock:
      per_split.append(split_hash)
    return _OK if split_hash.endswith("-ok") else _NOT_FOUND

  with caplog.at_level(logging.DEBUG, logger=logger.name):
    with mock.patch("subprocess.Popen", _fake_popen(result_for, batch_for)):
      assert inclusion_proof_check.perform_inclusion_proof_check(
          "/path/to/verifier", str(packages_file), logger, prefetch=False,
          progress=lambda *a: calls.append(a))

  # Only splits without a batch result were verified one by one.
  assert sorted(per_split) == ["a-ok", "m0-ok", "z0", "z2"]
  assert _results_by_hash(tmp_path) == _MANY_PACKAGES_RESULTS
  assert [c[0] for c in calls] == list(range(7))
  assert {c[1] for c in calls} == {6}

  warnings = [r.getMessage() for r in caplog.records
              if r.levelno == logging.WARNING]
  assert "com.m.middle [split 1]: Inclusion proof failed: inclusion check error" in warnings
  assert len([w for w in warnings if w.startswith("Ignoring ")]) == 5
  assert ("Batch verifier exited with code {} after 2 of 6 results; verifying "
          "the remaining 4 split(s) one at a time.".format(returncode)
          in warnings)
  assert "Batch verifier stderr: verifier log\n" in [
      r.getMessage() for r in caplog.records]


def test_perform_inclusion_proof_check_batch_crash_is_not_missing_batch_mode(
    tmp_path: Path, logger: logging.Logger, caplog: pytest.LogCaptureFixture
):
  """A Go panic also exits 2; only the flag error means an old verifier."""
  packages_file = _write_packages(tmp_path / "packages.txt", _many_packages())

  def batch_for(cmd):
    return 2, [], "panic: runtime error: index out of range\n\ngoroutine 1\n"

  def result_for(cmd):
    return _OK if _payload_of(cmd).split("\n")[0].endswith("-ok") else _NOT_FOUND

  with mock.patch("subprocess.Popen",
                  _fake_popen(result_for, batch_for)) as popen:
    assert inclusion_proof_check.perform_inclusion_proof_check(
        "/path/to/verifier", str(packages_file), logger, prefetch=False)

  # Every split is still verified, one per verifier run...
  assert len(_split_cmds(popen)) == 6
  assert _results_by_hash(tmp_path) == _MANY_PACKAGES_RESULTS
  # ...but the crash is reported as such.
  messages = [(r.levelno, r.getMessage()) for r in caplog.records]
  assert not any("does not support batch mode" in m for _, m in messages)
  assert (logging.WARNING,
          "Batch verifier exited with code 2 after 0 of 6 results; verifying "
          "the remaining 6 split(s) one at a time.") in messages


@pytest.mark.parametrize("executable", [False, True],
                         ids=["missing", "not_executable"])
def test_perform_inclusion_proof_check_batch_verifier_cannot_run(
    tmp_path: Path, logger: logging.Logger, caplog: pytest.LogCaptureFixture,
    executable: bool
):
  packages_file = _write_packages(tmp_path / "packages.txt", _many_packages())
  verifier = tmp_path / "verifier"
  if executable:
    verifier.write_text("not a program")
    verifier.chmod(0o644)

  with mock.patch("subprocess.Popen", wraps=subprocess.Popen) as popen:
    assert inclusion_proof_check.perform_inclusion_proof_check(
        str(verifier), str(packages_file), logger, prefetch=False)

  assert set(_results_by_hash(tmp_path).values()) == {False}
  assert len(_results_by_hash(tmp_path)) == 6
  # Tried once, in batch mode, not once more per split.
  assert popen.call_count == 1
  errors = [r.getMessage() for r in caplog.records
            if r.levelno == logging.ERROR]
  assert len(errors) == 1
  assert errors[0].startswith("Cannot run verifier `{}`".format(verifier))
  assert errors[0].endswith("Marking 6 split(s) as not verified.")


@pytest.mark.parametrize("error", [FileNotFoundError, PermissionError])
def test_perform_inclusion_proof_check_batch_temp_file_error_falls_back(
    tmp_path: Path, logger: logging.Logger, caplog: pytest.LogCaptureFixture,
    error: type
):
  """E.g. a bad TMPDIR is not blamed on the verifier."""
  packages_file = _write_packages(tmp_path / "packages.txt", _many_packages())

  def result_for(cmd):
    return _OK if _payload_of(cmd).split("\n")[0].endswith("-ok") else _NOT_FOUND

  with mock.patch.object(inclusion_proof_check, "_write_payloads_file",
                         side_effect=error("no temp dir")), \
       mock.patch("subprocess.Popen", _fake_popen(result_for)) as popen:
    assert inclusion_proof_check.perform_inclusion_proof_check(
        "/path/to/verifier", str(packages_file), logger, prefetch=False)

  assert not _batch_cmds(popen)
  assert len(_split_cmds(popen)) == 6
  assert _results_by_hash(tmp_path) == _MANY_PACKAGES_RESULTS
  messages = [r.getMessage() for r in caplog.records]
  assert "Could not prepare batch verification: no temp dir" in messages
  assert not any(m.startswith("Cannot run verifier") for m in messages)


def test_error_during_check_is_not_logged_as_interrupted(
    tmp_path: Path, logger: logging.Logger, caplog: pytest.LogCaptureFixture
):
  packages_file = _write_packages(tmp_path / "packages.txt", _many_packages())

  def progress(done, total):
    if done:
      raise RuntimeError("event stream broke")

  with mock.patch("subprocess.Popen", _fake_popen(lambda cmd: _OK)):
    with pytest.raises(RuntimeError):
      inclusion_proof_check.perform_inclusion_proof_check(
          "/path/to/verifier", str(packages_file), logger, prefetch=False,
          progress=progress)

  assert not any("interrupted" in r.getMessage() for r in caplog.records)


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


@pytest.mark.parametrize("error", [KeyboardInterrupt, RuntimeError])
def test_main_restores_sigterm_handler_on_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: type
):
  monkeypatch.setattr(sys, "argv", [
      "inclusion_proof_check.py",
      f"--packages_file={tmp_path / 'packages.txt'}",
      "--verifier_path=/path/to/verifier",
  ])
  before = signal.getsignal(signal.SIGTERM)
  with mock.patch.object(inclusion_proof_check,
                         "perform_inclusion_proof_check",
                         side_effect=error):
    with pytest.raises(error):
      inclusion_proof_check.main()
  assert signal.getsignal(signal.SIGTERM) == before


if __name__ == "__main__":
  sys.exit(pytest.main([__file__]))
