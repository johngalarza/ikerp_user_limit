# -*- coding: utf-8 -*-
"""JSON endpoint consumed by the in-app storage banner."""
from odoo import http
from odoo.http import request

from ..models.ikerp_storage import (
    PARAM_BREAKDOWN_DB_MB,
    PARAM_BREAKDOWN_FILESTORE_MB,
    PARAM_LIMIT_MB,
    PARAM_STATE,
    PARAM_USED_MB,
    STATE_OK,
)


def _int_param(env, key, default=0):
    raw = env["ir.config_parameter"].sudo().get_param(key)
    try:
        return int(raw) if raw not in (None, "") else default
    except (TypeError, ValueError):
        return default


class IkerpStorageController(http.Controller):

    @http.route("/ikerp/storage/state", type="json", auth="user")
    def storage_state(self):
        env = request.env
        state = env["ir.config_parameter"].sudo().get_param(PARAM_STATE) or STATE_OK
        used_mb = _int_param(env, PARAM_USED_MB)
        limit_mb = _int_param(env, PARAM_LIMIT_MB)
        db_mb = _int_param(env, PARAM_BREAKDOWN_DB_MB)
        filestore_mb = _int_param(env, PARAM_BREAKDOWN_FILESTORE_MB)
        pct = (used_mb / float(limit_mb)) if limit_mb > 0 else 0.0
        return {
            "state": state,
            "usedMB": used_mb,
            "limitMB": limit_mb or None,
            "pct": round(pct, 4),
            "breakdown": {"dbMB": db_mb, "filestoreMB": filestore_mb},
        }
