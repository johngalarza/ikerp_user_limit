# -*- coding: utf-8 -*-
from unittest import mock

from odoo.tests.common import TransactionCase

from odoo.addons.ikerp_user_limit.models.ikerp_security import (
    IkerpParamMissingError,
    IkerpSignatureInvalidError,
    compute_signature,
    verify_signed_param,
)


SECRET = "test-secret-please-rotate"


class TestSignedParams(TransactionCase):
    def setUp(self):
        super().setUp()
        self.ICP = self.env["ir.config_parameter"].sudo()
        self.env_patcher = mock.patch.dict(
            "os.environ", {"IKERP_SIGNING_SECRET": SECRET}
        )
        self.env_patcher.start()
        self.addCleanup(self.env_patcher.stop)

    def _set_signed(self, key, value, sig=None):
        self.ICP.set_param(key, str(value))
        if sig is None:
            sig = compute_signature(str(value), SECRET.encode("utf-8"))
        self.ICP.set_param(key + "_sig", sig)

    def test_valid_signature_returns_value(self):
        self._set_signed("ikerp.demo_param", "42")
        self.assertEqual(verify_signed_param(self.env, "ikerp.demo_param"), "42")

    def test_tampered_value_rejected(self):
        self._set_signed("ikerp.demo_param", "42")
        # Adversary raises the limit without re-signing.
        self.ICP.set_param("ikerp.demo_param", "9999")
        with self.assertRaises(IkerpSignatureInvalidError):
            verify_signed_param(self.env, "ikerp.demo_param")

    def test_missing_signature_rejected(self):
        self.ICP.set_param("ikerp.demo_param", "42")
        # No sibling _sig param set.
        with self.assertRaises(IkerpSignatureInvalidError):
            verify_signed_param(self.env, "ikerp.demo_param")

    def test_missing_param_raises_param_missing(self):
        with self.assertRaises(IkerpParamMissingError):
            verify_signed_param(self.env, "ikerp.never_set")

    def test_missing_secret_rejected(self):
        self._set_signed("ikerp.demo_param", "42")
        with mock.patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(IkerpSignatureInvalidError):
                verify_signed_param(self.env, "ikerp.demo_param")
