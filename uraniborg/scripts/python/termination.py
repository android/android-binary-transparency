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

"""Turns SIGTERM into an exception, so that scripts can clean up first.

SIGTERM is how CI timeouts and cancellations usually stop a process. By
default it kills the script at once, leaving e.g. child verifiers behind or
an event stream without its last event. Usage:

  terminated = False
  with termination.sigterm_raises():
    try:
      ...
    except termination.Terminated:
      terminated = True  # Clean up here.
  if terminated:
    termination.die_by_sigterm(logger)
"""

import contextlib
import logging
import os
import signal
import sys


class Terminated(BaseException):
  """Raised by the SIGTERM handler that sigterm_raises() installs.

  Derives from BaseException, like KeyboardInterrupt, so that the generic
  `except Exception` handlers do not swallow it. SyscallWrapper only catches
  KeyboardInterrupt, so this also propagates out of adb calls.
  """

  def __init__(self):
    super().__init__("received SIGTERM")


def raise_terminated(signum, frame):  # pylint: disable=unused-argument
  """SIGTERM handler that raises Terminated."""
  # Ignore repeated SIGTERMs while cleaning up; die_by_sigterm() restores the
  # default action afterwards.
  signal.signal(signal.SIGTERM, signal.SIG_IGN)
  raise Terminated()


@contextlib.contextmanager
def sigterm_raises():
  """Makes SIGTERM raise Terminated within the block.

  The previous handler is restored on leaving the block, however it is left.
  """
  previous = signal.signal(signal.SIGTERM, raise_terminated)
  try:
    yield
  finally:
    signal.signal(signal.SIGTERM, previous)


def die_by_sigterm(logger: logging.Logger) -> None:
  """Terminates this process with SIGTERM's default action.

  So the parent process sees the same exit status as without
  sigterm_raises().
  """
  logger.error("Terminated by SIGTERM.")
  signal.signal(signal.SIGTERM, signal.SIG_DFL)
  os.kill(os.getpid(), signal.SIGTERM)
  # Not reached unless SIGTERM is blocked; fall back to the conventional code.
  sys.exit(128 + signal.SIGTERM)
