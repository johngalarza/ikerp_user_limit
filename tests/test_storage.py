# -*- coding: utf-8 -*-
import os
from unittest import mock

from odoo.tests.common import TransactionCase

from odoo.addons.ikerp_user_limit.models import ikerp_storage as storage_mod
from odoo.addons.ikerp_user_limit.models.ikerp_security import compute_signature


SECRET = "test-secret"


class StorageTestBase(TransactionCase):
    def setUp(self):
        super().setUp()
        self.ICP = self.env["ir.config_parameter"].sudo()
        self.Storage = self.env["ikerp.storage"]
        self.env_patcher = mock.patch.dict(
            "os.environ",
            {"IKERP_SIGNING_SECRET": SECRET},
            clear=False,
        )
        self.env_patcher.start()
        self.addCleanup(self.env_patcher.stop)
        # Clean any prior state from the in-process cache so tests are isolated.
        storage_mod._state_cache.clear()

    def _set_limit(self, mb):
        sig = compute_signature(str(mb), SECRET.encode("utf-8"))
        self.ICP.set_param(storage_mod.PARAM_LIMIT_MB, str(mb))
        self.ICP.set_param(storage_mod.PARAM_LIMIT_MB + "_sig", sig)

    def _patch_usage(self, db_bytes, fs_bytes):
        return mock.patch.multiple(
            self.Storage.__class__,
            _measure_db_bytes=mock.MagicMock(return_value=db_bytes),
            _measure_filestore_bytes=mock.MagicMock(return_value=fs_bytes),
        )


class TestStorageMeasurement(StorageTestBase):
    def test_used_mb_rounds_up(self):
        # 1.5 MB total => ceil to 2 MB.
        with self._patch_usage(1024 * 1024, 512 * 1024):
            usage = self.Storage._measure_usage()
        self.assertEqual(usage["used_mb"], 2)

    def test_filestore_zero_when_path_absent(self):
        with mock.patch(
            "odoo.addons.ikerp_user_limit.models.ikerp_storage.os.path.isdir",
            return_value=False,
        ):
            self.assertEqual(self.Storage._measure_filestore_bytes(), 0)

    def test_filestore_sums_files_via_du(self, tmpdir=None):
        # Build a synthetic filestore tree under a temp dir.
        import tempfile

        with tempfile.TemporaryDirectory() as root:
            sub = os.path.join(root, "a", "b")
            os.makedirs(sub)
            with open(os.path.join(root, "f1"), "wb") as f:
                f.write(b"x" * 1000)
            with open(os.path.join(sub, "f2"), "wb") as f:
                f.write(b"y" * 234)
            with mock.patch(
                "odoo.tools.config.filestore", return_value=root,
            ):
                self.assertEqual(self.Storage._measure_filestore_bytes(), 1234)

    def test_filestore_falls_back_to_os_walk_when_du_missing(self):
        import tempfile

        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "f1"), "wb") as f:
                f.write(b"z" * 777)
            with mock.patch(
                "odoo.tools.config.filestore", return_value=root,
            ), mock.patch(
                "odoo.addons.ikerp_user_limit.models.ikerp_storage.subprocess.run",
                side_effect=FileNotFoundError(),
            ):
                self.assertEqual(self.Storage._measure_filestore_bytes(), 777)


class TestStorageTransitions(StorageTestBase):
    def setUp(self):
        super().setUp()
        self._set_limit(1000)  # 1000 MB plan
        self.posted = []
        self.post_patcher = mock.patch.object(
            self.Storage.__class__,
            "_post_alert",
            autospec=True,
            side_effect=lambda self_, payload: self.posted.append(payload) or True,
        )
        self.post_patcher.start()
        self.addCleanup(self.post_patcher.stop)
        # Avoid attempting to send mail in tests.
        self.email_patcher = mock.patch.object(
            self.Storage.__class__, "_send_admin_email", autospec=True,
        )
        self.email_patcher.start()
        self.addCleanup(self.email_patcher.stop)

    def _run_at_pct(self, pct):
        # Translate a target pct to bytes (db only for simplicity).
        target_mb = int(pct * 1000)
        target_bytes = target_mb * 1024 * 1024
        with self._patch_usage(target_bytes, 0):
            return self.Storage.recompute_and_dispatch()

    def test_under_warning_stays_ok(self):
        result = self._run_at_pct(0.50)
        self.assertEqual(result["state"], "ok")
        self.assertEqual(self.posted, [])

    def test_warning_threshold_posts_once(self):
        self._run_at_pct(0.50)
        self.posted.clear()
        self._run_at_pct(0.85)  # crosses 0.80 -> warning
        self.assertEqual(len(self.posted), 1)
        self.assertEqual(self.posted[0]["event"], "storage.warning")

        # Stays in warning -> no new POST.
        self._run_at_pct(0.88)
        self.assertEqual(len(self.posted), 1)

    def test_critical_then_blocked_posts_each_transition(self):
        self._run_at_pct(0.50)
        self.posted.clear()

        self._run_at_pct(0.96)  # warning -> critical (one transition step skipped)
        self.assertEqual(len(self.posted), 1)
        self.assertEqual(self.posted[-1]["event"], "storage.critical")

        self._run_at_pct(1.05)  # critical -> blocked
        self.assertEqual(len(self.posted), 2)
        self.assertEqual(self.posted[-1]["event"], "storage.blocked")

    def test_recovery_posts_recovered(self):
        self._run_at_pct(1.05)  # land in blocked
        self.posted.clear()
        self._run_at_pct(0.10)  # back to ok
        self.assertEqual(len(self.posted), 1)
        self.assertEqual(self.posted[0]["event"], "storage.recovered")


class TestStorageCompatibility(StorageTestBase):
    def test_missing_limit_param_keeps_ok(self):
        # No PARAM_LIMIT_MB set: legacy tenant.
        with self._patch_usage(0, 0):
            result = self.Storage.recompute_and_dispatch()
        self.assertEqual(result["state"], "ok")

    def test_invalid_signature_forces_blocked(self):
        self.ICP.set_param(storage_mod.PARAM_LIMIT_MB, "1000")
        self.ICP.set_param(storage_mod.PARAM_LIMIT_MB + "_sig", "deadbeef")
        with self._patch_usage(0, 0):
            result = self.Storage.recompute_and_dispatch()
        self.assertEqual(result["state"], "blocked")
