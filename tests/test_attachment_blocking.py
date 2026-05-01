# -*- coding: utf-8 -*-
from odoo.exceptions import UserError
from odoo.tests.common import TransactionCase, new_test_user

from odoo.addons.ikerp_user_limit.models import ikerp_storage as storage_mod


class TestAttachmentBlocking(TransactionCase):
    def setUp(self):
        super().setUp()
        self.ICP = self.env["ir.config_parameter"].sudo()
        # A non-superuser actor; the bypass exempts uid=1 / sudo() callers.
        self.actor = new_test_user(self.env, login="ikerp_actor", groups="base.group_user")
        # Reset the in-process state cache between tests.
        storage_mod._state_cache.clear()

    def _set_state(self, value):
        self.ICP.set_param(storage_mod.PARAM_STATE, value)
        storage_mod._state_cache.clear()

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
