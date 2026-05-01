# -*- coding: utf-8 -*-
"""Block ir.attachment writes that would grow the filestore once the tenant has
hit its signed storage cap (state == 'blocked'). unlink() stays open so the
user can free space.
"""
import logging

from odoo import _, api, models, SUPERUSER_ID
from odoo.exceptions import UserError

from .ikerp_storage import STATE_BLOCKED

_logger = logging.getLogger(__name__)

_GROWTH_FIELDS = ("datas", "raw", "db_datas", "store_fname")


class IrAttachment(models.Model):
    _inherit = "ir.attachment"

    def _ikerp_is_blocked(self):
        if self.env.uid == SUPERUSER_ID or self.env.su:
            return False
        return self.env["ikerp.storage"]._get_cached_state() == STATE_BLOCKED

    @staticmethod
    def _ikerp_raise_blocked():
        raise UserError(_(
            "Almacenamiento del plan excedido. Contacte al administrador para "
            "ampliar el plan."
        ))

    @api.model_create_multi
    def create(self, vals_list):
        if self._ikerp_is_blocked():
            self._ikerp_raise_blocked()
        return super().create(vals_list)

    def write(self, vals):
        if any(f in vals for f in _GROWTH_FIELDS) and self._ikerp_is_blocked():
            self._ikerp_raise_blocked()
        return super().write(vals)
