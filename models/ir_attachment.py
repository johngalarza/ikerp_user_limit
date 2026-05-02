# -*- coding: utf-8 -*-
"""Block ir.attachment writes that would grow the filestore past the tenant's
signed storage cap. The 30-min cron is too slow to catch a "fill the disk fast"
upload, so on every create/write we project usage = persisted + pending-delta +
this payload and trigger a synchronous recompute when the projection crosses a
threshold. unlink() stays open so the user can free space.
"""
import logging

from odoo import _, api, models, SUPERUSER_ID
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)

_GROWTH_FIELDS = ("datas", "raw", "db_datas", "store_fname")


class IrAttachment(models.Model):
    _inherit = "ir.attachment"

    @staticmethod
    def _ikerp_payload_bytes(vals):
        """Best-effort byte count for the attachment data carried in vals.

        Covers raw (bytes), datas (base64 str/bytes), and db_datas (bytes when
        Odoo forces inline storage). The base64 conversion is an upper-bound
        estimate — off by a few percent for padding, which is the safe
        direction for a quota gate.
        """
        raw = vals.get("raw")
        if isinstance(raw, (bytes, bytearray)):
            return len(raw)
        datas = vals.get("datas")
        if isinstance(datas, (bytes, bytearray)):
            return (len(datas) * 3) // 4
        if isinstance(datas, str):
            return (len(datas) * 3) // 4
        db_datas = vals.get("db_datas")
        if isinstance(db_datas, (bytes, bytearray)):
            return len(db_datas)
        return 0

    def _ikerp_should_block(self, payload_bytes):
        if self.env.uid == SUPERUSER_ID or self.env.su:
            return False
        return self.env["ikerp.storage"]._check_attachment_growth(payload_bytes)

    @staticmethod
    def _ikerp_raise_blocked():
        raise UserError(_(
            "Almacenamiento del plan excedido. Contacte al administrador para "
            "ampliar el plan."
        ))

    @api.model_create_multi
    def create(self, vals_list):
        total = sum(self._ikerp_payload_bytes(v) for v in vals_list)
        if self._ikerp_should_block(total):
            self._ikerp_raise_blocked()
        return super().create(vals_list)

    def write(self, vals):
        if any(f in vals for f in _GROWTH_FIELDS):
            # write() replaces file content; the old bytes will be GC'd
            # eventually but not before the recompute, so counting only the
            # new payload is a slight under-estimate. The next du -sb call
            # corrects it.
            if self._ikerp_should_block(self._ikerp_payload_bytes(vals)):
                self._ikerp_raise_blocked()
        return super().write(vals)
