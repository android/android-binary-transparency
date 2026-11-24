#!/usr/bin/env python3
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

"""Unit tests for pixel_factory_image_verify.py."""

import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

_VERIFIER_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
if _VERIFIER_TOOLS_DIR not in sys.path:
  sys.path.insert(0, _VERIFIER_TOOLS_DIR)

import pixel_factory_image_verify as verify  # pylint: disable=g-import-not-at-top

_GENERIC_FP = (
    'google/generic_system_google/generic:17/'
    'CP2A.260705.006/15641320:user/release-keys'
)
_PRE_A17_FP = (
    'google/panther/panther:16/BP2A.250605.031/12345678:user/release-keys'
)
_TOKAY_FP = 'google/tokay/tokay:17/CP2A.260705.006/15641320:user/release-keys'
_VENDOR_FP = 'google/tokay/tokay:17/VENDOR/15641320:user/release-keys'
_STRAY_FP = 'google/stray/stray:16/OLD/1:user/release-keys'


def _write_bytes(directory, filename, data):
  path = os.path.join(directory, filename)
  with open(path, 'wb') as f:
    f.write(data)
  return path


def _fake_completed(stdout='', stderr='', returncode=0):
  return subprocess.CompletedProcess(
      args=[sys.executable, 'avbtool.py'],
      returncode=returncode,
      stdout=stdout,
      stderr=stderr,
  )


class PixelFactoryImageVerifyTest(unittest.TestCase):

  def setUp(self):
    super().setUp()
    self._tempdir = tempfile.TemporaryDirectory()
    self.addCleanup(self._tempdir.cleanup)
    self.image_dir = self._tempdir.name
    self.verifier = verify.PixelFactoryImageVerifier()

  def test_avbtool_path_points_to_repo_submodule(self):
    repo_root = os.path.dirname(os.path.realpath(verify.__file__))
    expected = os.path.abspath(os.path.join(repo_root, '../avb/avbtool.py'))
    self.assertEqual(self.verifier.avbtool_path, expected)

  def test_system_img_device_specific_fingerprint(self):
    _write_bytes(
        self.image_dir,
        'system.img',
        b'\x00\x00ro.system.build.fingerprint=' + _PRE_A17_FP.encode() + b'\n\x00',
    )
    _write_bytes(
        self.image_dir,
        'product.img',
        b'ro.product.build.fingerprint='
        b'google/other/other:16/BP2A.250605.031/12345678:user/release-keys\n',
    )

    with mock.patch.object(subprocess, 'run') as mock_run:
      stdout = io.StringIO()
      with contextlib.redirect_stdout(stdout):
        fp = self.verifier._extract_build_fingerprint(self.image_dir)

    self.assertEqual(fp, _PRE_A17_FP)
    self.assertIn('Successfully extracted build fingerprint.', stdout.getvalue())
    mock_run.assert_not_called()

  def test_generic_system_prefers_signed_avb_product_prop_over_raw_product_img(
      self,
  ):
    _write_bytes(
        self.image_dir,
        'system.img',
        b'ro.system.build.fingerprint=' + _GENERIC_FP.encode() + b'\n',
    )
    _write_bytes(
        self.image_dir,
        'vbmeta_system.img',
        b'chain_system',
    )
    _write_bytes(
        self.image_dir,
        'product.img',
        b'ro.product.build.fingerprint=' + _STRAY_FP.encode() + b'\n',
    )

    def fake_run(cmd, **kwargs):
      del kwargs
      if cmd[-1].endswith('vbmeta_system.img'):
        return _fake_completed(
            stdout=(
                '    Prop: com.android.build.system.fingerprint -> '
                f"'{_GENERIC_FP}'\n"
                '    Prop: com.android.build.product.fingerprint -> '
                f"'{_TOKAY_FP}'\n"
            )
        )
      return _fake_completed(returncode=1, stderr='No AVB footer')

    with mock.patch.object(subprocess, 'run', side_effect=fake_run):
      stdout = io.StringIO()
      with contextlib.redirect_stdout(stdout):
        fp = self.verifier._extract_build_fingerprint(self.image_dir)

    self.assertEqual(fp, _TOKAY_FP)
    self.assertNotIn('Warning:', stdout.getvalue())
    self.assertNotIn('diagnostics', stdout.getvalue())

  def test_generic_system_falls_back_to_product_img_when_no_avb_prop(self):
    _write_bytes(
        self.image_dir,
        'system.img',
        b'ro.system.build.fingerprint=' + _GENERIC_FP.encode() + b'\n',
    )
    _write_bytes(
        self.image_dir,
        'product.img',
        b'ro.product.build.fingerprint=' + _TOKAY_FP.encode() + b'\n',
    )

    with mock.patch.object(
        subprocess, 'run', return_value=_fake_completed(returncode=1)
    ):
      stdout = io.StringIO()
      with contextlib.redirect_stdout(stdout):
        fp = self.verifier._extract_build_fingerprint(self.image_dir)

    self.assertEqual(fp, _TOKAY_FP)
    self.assertNotIn('Warning:', stdout.getvalue())

  def test_product_img_ignores_stray_other_partition_and_generic_props(self):
    _write_bytes(
        self.image_dir,
        'system.img',
        b'ro.system.build.fingerprint=' + _GENERIC_FP.encode() + b'\n',
    )
    _write_bytes(
        self.image_dir,
        'product.img',
        b'ro.boot.build.fingerprint=' + _STRAY_FP.encode() + b'\n'
        + b'ro.system.build.fingerprint=' + _STRAY_FP.encode() + b'\n'
        + b'ro.product.build.fingerprint=' + _GENERIC_FP.encode() + b'\n'
        + b'ro.product.build.fingerprint=' + _TOKAY_FP.encode() + b'\n',
    )

    with mock.patch.object(
        subprocess, 'run', return_value=_fake_completed(returncode=1)
    ):
      stdout = io.StringIO()
      with contextlib.redirect_stdout(stdout):
        fp = self.verifier._extract_build_fingerprint(self.image_dir)

    self.assertEqual(fp, _TOKAY_FP)

  def test_generic_system_stops_scanning_before_stray_fingerprint(self):
    _write_bytes(
        self.image_dir,
        'system.img',
        b'ro.build.fingerprint=google/\xff\xfe/release-keys\n'
        + b'ro.system_dlkm.build.fingerprint=' + _STRAY_FP.encode() + b'\n'
        + b'ro.system.build.fingerprint=' + _GENERIC_FP.encode() + b'\n'
        + b'ro.build.fingerprint=' + _STRAY_FP.encode() + b'\n',
    )
    _write_bytes(
        self.image_dir,
        'product.img',
        b'ro.product.build.fingerprint=' + _TOKAY_FP.encode() + b'\n',
    )

    with mock.patch.object(
        subprocess, 'run', return_value=_fake_completed(returncode=1)
    ):
      stdout = io.StringIO()
      with contextlib.redirect_stdout(stdout):
        fp = self.verifier._extract_build_fingerprint(self.image_dir)

    self.assertEqual(fp, _TOKAY_FP)

  def test_falls_back_to_avb_info_image_vbmeta_props(self):
    _write_bytes(
        self.image_dir,
        'system.img',
        b'ro.system.build.fingerprint=' + _GENERIC_FP.encode() + b'\n',
    )
    _write_bytes(self.image_dir, 'vbmeta.img', b'dummy_vbmeta')
    info_text = (
        '    Prop: com.android.build.system.fingerprint -> '
        f"'{_GENERIC_FP}'\n"
        '    Prop: com.android.build.vendor.fingerprint -> '
        f"'{_VENDOR_FP}'\n"
        '    Prop: com.android.build.product.fingerprint -> '
        f"'{_TOKAY_FP}'\n"
    )

    with mock.patch.object(
        subprocess, 'run', return_value=_fake_completed(stdout=info_text)
    ) as mock_run:
      stdout = io.StringIO()
      with contextlib.redirect_stdout(stdout):
        fp = self.verifier._extract_build_fingerprint(self.image_dir)

    self.assertEqual(fp, _TOKAY_FP)
    mock_run.assert_called_once()
    cmd = mock_run.call_args[0][0]
    self.assertEqual(
        cmd,
        [
            sys.executable,
            self.verifier.avbtool_path,
            'info_image',
            '--image',
            os.path.join(self.image_dir, 'vbmeta.img'),
        ],
    )

  def test_avb_system_prop_preferred_over_product_when_non_generic(self):
    _write_bytes(self.image_dir, 'vbmeta.img', b'dummy')
    info_text = (
        '    Prop: com.android.build.product.fingerprint -> '
        f"'{_TOKAY_FP}'\n"
        '    Prop: com.android.build.system.fingerprint -> '
        f"'{_PRE_A17_FP}'\n"
    )

    with mock.patch.object(
        subprocess, 'run', return_value=_fake_completed(stdout=info_text)
    ):
      stdout = io.StringIO()
      with contextlib.redirect_stdout(stdout):
        fp = self.verifier._extract_build_fingerprint(self.image_dir)

    self.assertEqual(fp, _PRE_A17_FP)

  def test_vendor_img_fallback_warns_and_ignores_stray_and_generic_props(self):
    _write_bytes(
        self.image_dir,
        'system.img',
        b'ro.system.build.fingerprint=' + _GENERIC_FP.encode() + b'\n',
    )
    _write_bytes(self.image_dir, 'vbmeta.img', b'not_avb')
    _write_bytes(
        self.image_dir,
        'vendor.img',
        b'ro.odm.build.fingerprint=' + _STRAY_FP.encode() + b'\n'
        + b'ro.vendor.build.fingerprint=' + _GENERIC_FP.encode() + b'\n'
        + b'ro.vendor.build.fingerprint=' + _VENDOR_FP.encode() + b'\n',
    )

    with mock.patch.object(
        subprocess, 'run', return_value=_fake_completed(returncode=1)
    ):
      stdout = io.StringIO()
      with contextlib.redirect_stdout(stdout):
        fp = self.verifier._extract_build_fingerprint(self.image_dir)

    self.assertEqual(fp, _VENDOR_FP)
    out = stdout.getvalue()
    self.assertIn(
        'Warning: falling back to vendor build fingerprint',
        out,
    )
    self.assertIn('avbtool info_image diagnostics:', out)
    self.assertIn('vbmeta.img: exited with code 1', out)

  def test_avb_vendor_prop_fallback_warns_and_preferred_over_raw_vendor_img(
      self,
  ):
    _write_bytes(
        self.image_dir,
        'system.img',
        b'ro.system.build.fingerprint=' + _GENERIC_FP.encode() + b'\n',
    )
    _write_bytes(self.image_dir, 'vbmeta_vendor.img', b'chain_vendor')
    _write_bytes(
        self.image_dir,
        'vendor.img',
        b'ro.vendor.build.fingerprint=' + _STRAY_FP.encode() + b'\n',
    )

    def fake_run(cmd, **kwargs):
      del kwargs
      if cmd[-1].endswith('vbmeta_vendor.img'):
        return _fake_completed(
            stdout=(
                '    Prop: com.android.build.vendor.fingerprint -> '
                f"'{_VENDOR_FP}'\n"
            )
        )
      return _fake_completed(returncode=1, stderr='No AVB footer')

    with mock.patch.object(subprocess, 'run', side_effect=fake_run):
      stdout = io.StringIO()
      with contextlib.redirect_stdout(stdout):
        fp = self.verifier._extract_build_fingerprint(self.image_dir)

    self.assertEqual(fp, _VENDOR_FP)
    out = stdout.getvalue()
    self.assertIn(
        'Warning: falling back to vendor build fingerprint',
        out,
    )
    self.assertIn('avbtool info_image diagnostics:', out)
    self.assertIn('vendor.img: exited with code 1 (No AVB footer)', out)

  def test_avb_oserror_does_not_abort_vendor_fallback(self):
    _write_bytes(
        self.image_dir,
        'system.img',
        b'ro.system.build.fingerprint=' + _GENERIC_FP.encode() + b'\n',
    )
    _write_bytes(self.image_dir, 'vbmeta.img', b'dummy')
    _write_bytes(
        self.image_dir,
        'vendor.img',
        b'ro.vendor.build.fingerprint=' + _VENDOR_FP.encode() + b'\n',
    )

    with mock.patch.object(
        subprocess, 'run', side_effect=FileNotFoundError('avbtool.py missing')
    ):
      stdout = io.StringIO()
      with contextlib.redirect_stdout(stdout):
        fp = self.verifier._extract_build_fingerprint(self.image_dir)

    self.assertEqual(fp, _VENDOR_FP)
    out = stdout.getvalue()
    self.assertIn(
        'Warning: falling back to vendor build fingerprint',
        out,
    )
    self.assertIn('avbtool info_image diagnostics:', out)
    self.assertIn('vbmeta.img: avbtool.py missing', out)

  def test_generic_only_returns_none_and_prints_avb_diagnostics(self):
    _write_bytes(
        self.image_dir,
        'system.img',
        b'ro.system.build.fingerprint=' + _GENERIC_FP.encode() + b'\n',
    )
    _write_bytes(self.image_dir, 'vbmeta.img', b'corrupt_vbmeta')
    _write_bytes(self.image_dir, 'product.img', b'no_prop_here')

    def fake_run(cmd, **kwargs):
      del kwargs
      if cmd[-1].endswith('vbmeta.img'):
        return _fake_completed(returncode=1, stderr='Given image is corrupt')
      raise PermissionError('Permission denied')

    with mock.patch.object(subprocess, 'run', side_effect=fake_run):
      stdout = io.StringIO()
      with contextlib.redirect_stdout(stdout):
        fp = self.verifier._extract_build_fingerprint(self.image_dir)

    self.assertIsNone(fp)
    out = stdout.getvalue()
    self.assertIn('avbtool info_image diagnostics:', out)
    self.assertIn('vbmeta.img: exited with code 1 (Given image is corrupt)', out)
    self.assertIn('product.img: Permission denied', out)
    self.assertIn('Build fingerprint extraction failed.', out)

  def test_verify_and_digest_invoke_avbtool_via_sys_executable(self):
    with mock.patch.object(
        self.verifier, '_run_command', return_value=(True, 'deadbeef\n')
    ) as mock_run:
      self.assertTrue(self.verifier._verify_vbmeta_partitions(self.image_dir))
      self.assertEqual(
          self.verifier._calculate_vbmeta_digest(self.image_dir), 'deadbeef\n'
      )

    self.assertEqual(
        mock_run.call_args_list[0][0][0][:3],
        [sys.executable, self.verifier.avbtool_path, 'verify_image'],
    )
    self.assertEqual(
        mock_run.call_args_list[1][0][0][:3],
        [sys.executable, self.verifier.avbtool_path, 'calculate_vbmeta_digest'],
    )

  def test_scan_across_chunk_boundary(self):
    content = (
        b'\x00' * 720
        + b'ro.build.fingerprint=' + _PRE_A17_FP.encode() + b'\n'
        + b'\x00' * 200
    )
    path = _write_bytes(self.image_dir, 'system.img', content)

    fp = verify._scan_partition_fingerprint(
        path, chunk_size=256, scan_overlap=128
    )

    self.assertEqual(fp, _PRE_A17_FP)

  def test_scan_non_greedy_match_stops_at_first_release_keys(self):
    content = (
        b'ro.product.build.fingerprint='
        + _TOKAY_FP.encode()
        + b',trailing/release-keys\n'
    )
    path = _write_bytes(self.image_dir, 'product.img', content)

    self.assertEqual(
        verify._scan_partition_fingerprint(
            path, pattern=verify._PRODUCT_FINGERPRINT_PATTERN
        ),
        _TOKAY_FP,
    )

  def test_scan_skips_invalid_utf8_before_valid_fingerprint(self):
    content = (
        b'ro.build.fingerprint=google/\xff\xfe/release-keys\n'
        + b'ro.system.build.fingerprint=' + _TOKAY_FP.encode() + b'\r\n'
    )
    path = _write_bytes(self.image_dir, 'system.img', content)

    self.assertEqual(verify._scan_partition_fingerprint(path), _TOKAY_FP)

  def test_scan_zero_overlap_handles_empty_tail(self):
    path = _write_bytes(
        self.image_dir,
        'product.img',
        b'no fingerprint here' * 50,
    )

    self.assertIsNone(
        verify._scan_partition_fingerprint(path, chunk_size=64, scan_overlap=0)
    )

  def test_extract_build_fingerprint_preserves_cwd(self):
    cwd_before = os.getcwd()
    _write_bytes(
        self.image_dir,
        'product.img',
        b'ro.product.build.fingerprint=' + _TOKAY_FP.encode() + b'\n',
    )

    with mock.patch.object(
        subprocess, 'run', return_value=_fake_completed(returncode=1)
    ):
      stdout = io.StringIO()
      with contextlib.redirect_stdout(stdout):
        fp = self.verifier._extract_build_fingerprint(self.image_dir)

    self.assertEqual(fp, _TOKAY_FP)
    self.assertEqual(os.getcwd(), cwd_before)

  def test_run_exits_with_hint_when_avbtool_missing(self):
    self.verifier.avbtool_path = os.path.join(
        self.image_dir, 'missing_avbtool.py'
    )
    stdout = io.StringIO()
    with mock.patch.object(
        verify.shutil, 'which', return_value='/usr/bin/unzip'
    ):
      with contextlib.redirect_stdout(stdout):
        with self.assertRaises(SystemExit) as cm:
          self.verifier.run(['pixel_factory_image_verify.py', 'image.zip'])

    self.assertEqual(cm.exception.code, 1)
    self.assertIn('git submodule update --init --recursive', stdout.getvalue())


if __name__ == '__main__':
  unittest.main()
