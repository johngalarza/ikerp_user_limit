# -*- coding: utf-8 -*-
from datetime import datetime, timedelta, timezone
from unittest import mock

from odoo.exceptions import UserError
from odoo.tests.common import TransactionCase, new_test_user

from odoo.addons.ikerp_user_limit.models import ikerp_storage as storage_mod
from odoo.addons.ikerp_user_limit.models.ikerp_security import compute_signature


SECRET = "test-secret"


class TestAttachmentBlocking(TransactionCase):
    def setUp(self):
        super().setUp()
        self.ICP = self.env["ir.config_parameter"].sudo()
        # A non-superuser actor; the bypass exempts uid=1 / sudo() callers.
        self.actor = new_test_user(self.env, login="ikerp_actor", groups="base.group_user")
        # Reset the in-process caches between tests.
        storage_mod._state_cache.clear()
        storage_mod._pending_growth_bytes.clear()
        self.env_patcher = mock.patch.dict(
            "os.environ",
            {"IKERP_SIGNING_SECRET": SECRET},
            clear=False,
        )
        self.env_patcher.start()
        self.addCleanup(self.env_patcher.stop)
        # Sign a baseline limit so the verified-state read enters the
        # enforcement branch. Tests that need legacy behavior can clear it.
        self._set_signed(storage_mod.PARAM_LIMIT_MB, "1000")

    def _set_signed(self, param, value):
        self.ICP.set_param(param, str(value))
        self.ICP.set_param(
            param + "_sig",
            compute_signature(str(value), SECRET.encode("utf-8")),
        )

    def _fresh_iso(self):
        return datetime.now(timezone.utc).strftime(
            storage_mod.LAST_RUN_TIMESTAMP_FORMAT,
        )

    def _set_state(self, value):
        # Full signed snapshot: state + fresh last_run_at, mirroring what the
        # cron writes. Tests can override one piece to simulate tampering.
        self._set_signed(storage_mod.PARAM_STATE, value)
        self._set_signed(storage_mod.PARAM_LAST_RUN_AT, self._fresh_iso())
        storage_mod._state_cache.clear()
        storage_mod._pending_growth_bytes.clear()

    def _set_used_mb(self, used_mb):
        self.ICP.set_param(storage_mod.PARAM_USED_MB, str(used_mb))
        storage_mod._state_cache.clear()
        storage_mod._pending_growth_bytes.clear()

    def _mock_measure(self, used_mb):
        """Return a _measure_usage replacement that yields a fixed used_mb.

        Lets tests drive recompute_and_dispatch deterministically without
        actually walking the filestore — du -sb in tests would pick up
        unrelated bytes from the dev environment.
        """
        return mock.patch.object(
            type(self.env["ikerp.storage"]),
            "_measure_usage",
            autospec=True,
            return_value={
                "db_bytes": 0,
                "filestore_bytes": used_mb * 1024 * 1024,
                "db_mb": 0,
                "filestore_mb": used_mb,
                "used_mb": used_mb,
            },
        )

    def test_create_blocked_when_state_blocked(self):
        self._set_state("blocked")
        Attachment = self.env["ir.attachment"].with_user(self.actor)
        with self.assertRaises(UserError):
            Attachment.create({
                "name": "test.bin",
                "raw": b"hello",
            })

    def test_create_allowed_when_state_ok(self):
        self._set_state("ok")
        Attachment = self.env["ir.attachment"].with_user(self.actor)
        att = Attachment.create({
            "name": "test.bin",
            "raw": b"hello",
        })
        self.assertTrue(att.id)

    def test_write_growth_field_blocked(self):
        self._set_state("ok")
        att = self.env["ir.attachment"].with_user(self.actor).create({
            "name": "test.bin",
            "raw": b"hello",
        })
        self._set_state("blocked")
        with self.assertRaises(UserError):
            att.write({"raw": b"more data"})

    def test_write_metadata_only_allowed_when_blocked(self):
        self._set_state("ok")
        att = self.env["ir.attachment"].with_user(self.actor).create({
            "name": "test.bin",
            "raw": b"hello",
        })
        self._set_state("blocked")
        # Only renaming — no growth field touched. Should pass.
        att.write({"name": "renamed.bin"})
        self.assertEqual(att.name, "renamed.bin")

    def test_unlink_allowed_when_blocked(self):
        self._set_state("ok")
        att = self.env["ir.attachment"].with_user(self.actor).create({
            "name": "test.bin",
            "raw": b"hello",
        })
        self._set_state("blocked")
        att.unlink()
        self.assertFalse(att.exists())

    def test_superuser_bypasses_block(self):
        self._set_state("blocked")
        att = self.env["ir.attachment"].sudo().create({
            "name": "test.bin",
            "raw": b"hello",
        })
        self.assertTrue(att.id)

    def test_tampered_state_value_fails_closed(self):
        # Adversary edits storage_state from "blocked" to "ok" via debug
        # without re-signing — verified read must reject and block.
        self._set_state("blocked")
        self.ICP.set_param(storage_mod.PARAM_STATE, "ok")
        storage_mod._state_cache.clear()
        Attachment = self.env["ir.attachment"].with_user(self.actor)
        with self.assertRaises(UserError):
            Attachment.create({"name": "test.bin", "raw": b"hello"})

    def test_missing_state_signature_fails_closed(self):
        # Adversary deletes the _sig sibling but keeps the value.
        self._set_state("ok")
        self.ICP.set_param(storage_mod.PARAM_STATE + "_sig", False)
        storage_mod._state_cache.clear()
        Attachment = self.env["ir.attachment"].with_user(self.actor)
        with self.assertRaises(UserError):
            Attachment.create({"name": "test.bin", "raw": b"hello"})

    def test_stale_last_run_fails_closed(self):
        # Cron disabled / dead: last_run_at signed but older than the budget.
        self._set_signed(storage_mod.PARAM_STATE, "ok")
        stale = datetime.now(timezone.utc) - timedelta(
            seconds=storage_mod.STALENESS_BUDGET_SECONDS + 60,
        )
        self._set_signed(
            storage_mod.PARAM_LAST_RUN_AT,
            stale.strftime(storage_mod.LAST_RUN_TIMESTAMP_FORMAT),
        )
        storage_mod._state_cache.clear()
        Attachment = self.env["ir.attachment"].with_user(self.actor)
        with self.assertRaises(UserError):
            Attachment.create({"name": "test.bin", "raw": b"hello"})

    def test_missing_last_run_param_fails_closed(self):
        # Adversary deletes last_run_at entirely.
        self._set_signed(storage_mod.PARAM_STATE, "ok")
        self.ICP.set_param(storage_mod.PARAM_LAST_RUN_AT, False)
        self.ICP.set_param(storage_mod.PARAM_LAST_RUN_AT + "_sig", False)
        storage_mod._state_cache.clear()
        Attachment = self.env["ir.attachment"].with_user(self.actor)
        with self.assertRaises(UserError):
            Attachment.create({"name": "test.bin", "raw": b"hello"})

    # ------------------------------------------------------------------
    # Projection / fast-fill detection
    # ------------------------------------------------------------------
    def test_projection_blocks_when_payload_pushes_over_limit(self):
        # 10 MB cap, 8 MB persisted, 5 MB upload -> projected 13 MB.
        # The new file isn't on disk yet during create(), so the recompute's
        # measure call still sees 8 MB. The gate must use the projection,
        # not the recomputed state, to refuse the write.
        self._set_signed(storage_mod.PARAM_LIMIT_MB, "10")
        self._set_state("ok")
        self._set_used_mb(8)
        with self._mock_measure(8):
            Attachment = self.env["ir.attachment"].with_user(self.actor)
            with self.assertRaises(UserError):
                Attachment.create({
                    "name": "big.bin",
                    "raw": b"x" * (5 * 1024 * 1024),
                })

    def test_projection_under_threshold_skips_recompute(self):
        # Plenty of headroom: 1000 MB cap, 100 MB persisted, 5 byte upload.
        # The hot path must not invoke the disk-walking recompute for this.
        self._set_state("ok")
        self._set_used_mb(100)
        Storage = type(self.env["ikerp.storage"])
        with mock.patch.object(
            Storage, "recompute_and_dispatch", autospec=True,
        ) as recompute:
            att = self.env["ir.attachment"].with_user(self.actor).create({
                "name": "small.bin",
                "raw": b"hello",
            })
            self.assertTrue(att.id)
            recompute.assert_not_called()

    def test_projection_crossing_warning_triggers_recompute(self):
        # 1000 MB cap, 750 MB persisted, 50 MB upload -> projected 800 MB
        # = warning threshold. Crossing ok -> warning must trigger one
        # synchronous recompute so the banner / alerts catch up.
        self._set_signed(storage_mod.PARAM_LIMIT_MB, "1000")
        self._set_state("ok")
        self._set_used_mb(750)
        Storage = type(self.env["ikerp.storage"])
        original = Storage.recompute_and_dispatch
        with self._mock_measure(750), mock.patch.object(
            Storage, "recompute_and_dispatch", autospec=True,
            side_effect=original,
        ) as recompute:
            att = self.env["ir.attachment"].with_user(self.actor).create({
                "name": "chunk.bin",
                "raw": b"x" * (50 * 1024 * 1024),
            })
            self.assertTrue(att.id)
            self.assertEqual(recompute.call_count, 1)

    def test_pending_delta_accumulates_across_calls(self):
        # 100 MB cap, 70 MB persisted. Two consecutive 5 MB writes from the
        # same worker: first projects to 75 MB (ok, no recompute), second
        # must see the first's 5 MB pending delta and project to 80 MB,
        # crossing the 80% warning threshold and triggering a recompute.
        # Mocking recompute as a no-op also verifies the pending delta is
        # not silently reset by anything other than _invalidate_state_cache.
        self._set_signed(storage_mod.PARAM_LIMIT_MB, "100")
        self._set_state("ok")
        self._set_used_mb(70)
        Storage = type(self.env["ikerp.storage"])
        Attachment = self.env["ir.attachment"].with_user(self.actor)
        with mock.patch.object(
            Storage, "recompute_and_dispatch", autospec=True,
        ) as recompute:
            Attachment.create({
                "name": "a.bin",
                "raw": b"x" * (5 * 1024 * 1024),
            })
            self.assertEqual(recompute.call_count, 0)
            Attachment.create({
                "name": "b.bin",
                "raw": b"x" * (5 * 1024 * 1024),
            })
            self.assertEqual(recompute.call_count, 1)

    def test_unconfigured_limit_stays_legacy_ok(self):
        # No signed limit -> legacy/forward-compat tenant: don't enforce even
        # if state/last_run are missing.
        self.ICP.set_param(storage_mod.PARAM_LIMIT_MB, False)
        self.ICP.set_param(storage_mod.PARAM_LIMIT_MB + "_sig", False)
        self.ICP.set_param(storage_mod.PARAM_STATE, False)
        self.ICP.set_param(storage_mod.PARAM_LAST_RUN_AT, False)
        storage_mod._state_cache.clear()
        att = self.env["ir.attachment"].with_user(self.actor).create({
            "name": "test.bin",
            "raw": b"hello",
        })
        self.assertTrue(att.id)
