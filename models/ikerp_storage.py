# -*- coding: utf-8 -*-
"""IKERP per-tenant storage monitor.

Recomputes (DB + filestore) usage on a 30-min cron, compares against the
HMAC-signed plan limit, transitions through ok/warning/critical/blocked, and
notifies the IKERP backend on every upward transition. The same state value
gates ir.attachment writes (see ir_attachment.py).
"""
import logging
import math
import os
import time
from datetime import datetime, timezone

from odoo import api, models, tools

from .ikerp_security import (
    IkerpParamMissingError,
    IkerpSignatureError,
    verify_signed_param,
)

_logger = logging.getLogger(__name__)

PARAM_LIMIT_MB = "ikerp.storage_limit_mb"
PARAM_USED_MB = "ikerp.storage_used_mb"
PARAM_STATE = "ikerp.storage_state"
PARAM_BREAKDOWN_DB_MB = "ikerp.storage_db_mb"
PARAM_BREAKDOWN_FILESTORE_MB = "ikerp.storage_filestore_mb"
PARAM_ADMIN_EMAIL = "ikerp.admin_email"
PARAM_INSTANCE_ID_FALLBACK = "ikerp.instance_id"

ENV_ALERTS_URL = "IKERP_ALERTS_URL"
ENV_METRICS_TOKEN = "IKERP_METRICS_TOKEN"
ENV_INSTANCE_ID = "IKERP_INSTANCE_ID"

STATE_OK = "ok"
STATE_WARNING = "warning"
STATE_CRITICAL = "critical"
STATE_BLOCKED = "blocked"

STATE_RANK = {
    STATE_OK: 0,
    STATE_WARNING: 1,
    STATE_CRITICAL: 2,
    STATE_BLOCKED: 3,
}

THRESHOLD_WARNING = 0.80
THRESHOLD_CRITICAL = 0.95
THRESHOLD_BLOCKED = 1.00

EVENT_FOR_STATE = {
    STATE_WARNING: "storage.warning",
    STATE_CRITICAL: "storage.critical",
    STATE_BLOCKED: "storage.blocked",
}

HTTP_TIMEOUT_SECONDS = 10
HTTP_RETRY_BACKOFF_SECONDS = 5

# Module-level cache for ir.attachment hot-path reads. Keyed by (dbname,) so a
# single worker serving multiple DBs stays correct.
_STATE_CACHE_TTL_SECONDS = 60
_state_cache = {}


def _now_utc_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _bytes_to_mb_ceil(n_bytes):
    return int(math.ceil(n_bytes / (1024.0 * 1024.0)))


class IkerpStorage(models.AbstractModel):
    _name = "ikerp.storage"
    _description = "IKERP storage quota monitor"

    # ------------------------------------------------------------------
    # Measurement
    # ------------------------------------------------------------------
    def _measure_db_bytes(self):
        self.env.cr.execute("SELECT pg_database_size(current_database())")
        row = self.env.cr.fetchone()
        return int(row[0]) if row and row[0] is not None else 0

    def _measure_filestore_bytes(self):
        path = tools.config.filestore(self.env.cr.dbname)
        if not path or not os.path.isdir(path):
            return 0
        total = 0
        for dirpath, _dirs, files in os.walk(path):
            for fname in files:
                fpath = os.path.join(dirpath, fname)
                try:
                    total += os.path.getsize(fpath)
                except OSError:
                    # File may have been GC'd between walk and stat — ignore.
                    continue
        return total

    def _measure_usage(self):
        """Return dict with measured bytes and MB-rounded fields."""
        db_bytes = self._measure_db_bytes()
        fs_bytes = self._measure_filestore_bytes()
        return {
            "db_bytes": db_bytes,
            "filestore_bytes": fs_bytes,
            "db_mb": _bytes_to_mb_ceil(db_bytes),
            "filestore_mb": _bytes_to_mb_ceil(fs_bytes),
            "used_mb": _bytes_to_mb_ceil(db_bytes + fs_bytes),
        }

    # ------------------------------------------------------------------
    # Limit (signed) lookup
    # ------------------------------------------------------------------
    def _get_signed_limit_mb(self):
        """Return (limit_mb: int|None, status: str).

        status is one of:
            'ok'           - limit found and HMAC-verified.
            'not_configured' - param absent (compat: legacy tenant without limit yet).
            'invalid'      - secret missing, sig missing, or HMAC mismatch (treat as blocked).
        """
        try:
            raw = verify_signed_param(self.env, PARAM_LIMIT_MB)
        except IkerpParamMissingError:
            return None, "not_configured"
        except IkerpSignatureError:
            return None, "invalid"

        try:
            limit = int(raw)
        except (TypeError, ValueError):
            _logger.error("IKERP storage: storage_limit_mb=%r is not an int.", raw)
            return None, "invalid"

        if limit <= 0:
            _logger.error("IKERP storage: non-positive storage_limit_mb=%s", limit)
            return None, "invalid"

        return limit, "ok"

    # ------------------------------------------------------------------
    # State derivation
    # ------------------------------------------------------------------
    @staticmethod
    def _state_for(pct):
        if pct >= THRESHOLD_BLOCKED:
            return STATE_BLOCKED
        if pct >= THRESHOLD_CRITICAL:
            return STATE_CRITICAL
        if pct >= THRESHOLD_WARNING:
            return STATE_WARNING
        return STATE_OK

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _read_state(self):
        return self.env["ir.config_parameter"].sudo().get_param(PARAM_STATE) or STATE_OK

    def _write_snapshot(self, state, used_mb, db_mb, filestore_mb):
        ICP = self.env["ir.config_parameter"].sudo()
        ICP.set_param(PARAM_STATE, state)
        ICP.set_param(PARAM_USED_MB, str(used_mb))
        ICP.set_param(PARAM_BREAKDOWN_DB_MB, str(db_mb))
        ICP.set_param(PARAM_BREAKDOWN_FILESTORE_MB, str(filestore_mb))

    # ------------------------------------------------------------------
    # Backend POST
    # ------------------------------------------------------------------
    def _post_alert(self, payload):
        """POST a state-transition alert to the IKERP backend.

        Failures are logged but never raised — the cron must not be derailed by
        a flaky control plane.
        """
        url = os.environ.get(ENV_ALERTS_URL)
        if not url:
            _logger.info(
                "IKERP storage: %s not set; skipping alert POST for event=%s.",
                ENV_ALERTS_URL, payload.get("event"),
            )
            return False

        token = os.environ.get(ENV_METRICS_TOKEN)
        instance_id = os.environ.get(ENV_INSTANCE_ID) or self.env[
            "ir.config_parameter"
        ].sudo().get_param(PARAM_INSTANCE_ID_FALLBACK)
        if not token or not instance_id:
            _logger.warning(
                "IKERP storage: missing %s or %s; cannot authenticate alert.",
                ENV_METRICS_TOKEN, ENV_INSTANCE_ID,
            )
            return False

        # Lazy import: keeps unit tests that don't touch HTTP from needing requests.
        import requests

        headers = {
            "Authorization": "Bearer %s" % token,
            "X-Instance-Id": instance_id,
            "Content-Type": "application/json",
        }
        attempts = 0
        last_exc = None
        while attempts < 2:
            try:
                resp = requests.post(
                    url, json=payload, headers=headers, timeout=HTTP_TIMEOUT_SECONDS,
                )
                if 200 <= resp.status_code < 300:
                    return True
                _logger.warning(
                    "IKERP storage: alert POST returned %s: %s",
                    resp.status_code, resp.text[:200],
                )
            except requests.RequestException as exc:
                last_exc = exc
                _logger.warning("IKERP storage: alert POST failed: %s", exc)
            attempts += 1
            if attempts < 2:
                time.sleep(HTTP_RETRY_BACKOFF_SECONDS)
        if last_exc:
            _logger.error("IKERP storage: alert POST giving up: %s", last_exc)
        return False

    # ------------------------------------------------------------------
    # Email
    # ------------------------------------------------------------------
    def _resolve_admin_user(self):
        """Find the tenant admin to email. Prefer the ikerp.admin_email config
        param; fall back to the standard base.user_admin xmlid.
        """
        admin_email = self.env["ir.config_parameter"].sudo().get_param(PARAM_ADMIN_EMAIL)
        if admin_email:
            user = self.env["res.users"].sudo().search(
                [("login", "=", admin_email)], limit=1,
            )
            if user:
                return user
        return self.env.ref("base.user_admin", raise_if_not_found=False)

    def _send_admin_email(self, state, payload):
        admin = self._resolve_admin_user()
        if not admin or not admin.email:
            _logger.info(
                "IKERP storage: no admin user/email resolved; skipping notification.",
            )
            return
        template = self.env.ref(
            "ikerp_user_limit.mail_template_storage_alert",
            raise_if_not_found=False,
        )
        if not template:
            _logger.warning("IKERP storage: mail template not found; skipping email.")
            return
        ctx = {
            "ikerp_state": state,
            "ikerp_used_mb": payload["usedMB"],
            "ikerp_limit_mb": payload["limitMB"],
            "ikerp_pct": int(round(payload["pct"] * 100)),
            "ikerp_admin_email": admin.email,
        }
        template.with_context(**ctx).send_mail(admin.id, force_send=False)

    # ------------------------------------------------------------------
    # Public API: full recompute + transitions
    # ------------------------------------------------------------------
    def recompute_and_dispatch(self):
        """Measure, persist, transition, notify. Called by cron and tests."""
        prev_state = self._read_state()
        limit_mb, status = self._get_signed_limit_mb()

        if status == "not_configured":
            _logger.info("IKERP storage: storage limit not configured; staying ok.")
            usage = self._measure_usage()
            self._write_snapshot(
                STATE_OK, usage["used_mb"], usage["db_mb"], usage["filestore_mb"],
            )
            self._invalidate_state_cache()
            return {
                "state": STATE_OK,
                "limit_mb": None,
                "used_mb": usage["used_mb"],
                "pct": 0.0,
                "transition": prev_state != STATE_OK,
            }

        if status == "invalid":
            # Fail closed: tampering or misconfig of the secret pipeline.
            usage = self._measure_usage()
            new_state = STATE_BLOCKED
            self._write_snapshot(
                new_state, usage["used_mb"], usage["db_mb"], usage["filestore_mb"],
            )
            self._invalidate_state_cache()
            self._maybe_notify_transition(prev_state, new_state, {
                "event": EVENT_FOR_STATE[STATE_BLOCKED],
                "usedMB": usage["used_mb"],
                "limitMB": None,
                "pct": None,
                "breakdown": {
                    "dbMB": usage["db_mb"],
                    "filestoreMB": usage["filestore_mb"],
                },
                "occurredAt": _now_utc_iso(),
                "reason": "signature_invalid",
            })
            return {
                "state": new_state,
                "limit_mb": None,
                "used_mb": usage["used_mb"],
                "pct": None,
                "transition": prev_state != new_state,
            }

        usage = self._measure_usage()
        pct = (usage["used_mb"] / float(limit_mb)) if limit_mb > 0 else 1.0
        new_state = self._state_for(pct)
        self._write_snapshot(
            new_state, usage["used_mb"], usage["db_mb"], usage["filestore_mb"],
        )
        self._invalidate_state_cache()

        payload = {
            "event": EVENT_FOR_STATE.get(new_state, "storage.recovered"),
            "usedMB": usage["used_mb"],
            "limitMB": limit_mb,
            "pct": round(pct, 4),
            "breakdown": {
                "dbMB": usage["db_mb"],
                "filestoreMB": usage["filestore_mb"],
            },
            "occurredAt": _now_utc_iso(),
        }
        self._maybe_notify_transition(prev_state, new_state, payload)

        return {
            "state": new_state,
            "limit_mb": limit_mb,
            "used_mb": usage["used_mb"],
            "pct": pct,
            "transition": prev_state != new_state,
        }

    def _maybe_notify_transition(self, prev_state, new_state, payload):
        """Notify backend (and admin) on any transition; classify direction."""
        if prev_state == new_state:
            return
        prev_rank = STATE_RANK.get(prev_state, 0)
        new_rank = STATE_RANK.get(new_state, 0)

        if new_rank > prev_rank:
            # Upward: warning/critical/blocked event.
            self._post_alert(payload)
            if new_state in (STATE_CRITICAL, STATE_BLOCKED):
                try:
                    self._send_admin_email(new_state, payload)
                except Exception:
                    _logger.exception("IKERP storage: admin email dispatch failed.")
        else:
            # Downward: backend wants to know we recovered too.
            recovered = dict(payload)
            recovered["event"] = "storage.recovered"
            self._post_alert(recovered)

    # ------------------------------------------------------------------
    # Cache helpers (used by ir.attachment fast path)
    # ------------------------------------------------------------------
    def _invalidate_state_cache(self):
        _state_cache.pop(self.env.cr.dbname, None)

    @api.model
    def _get_cached_state(self):
        """Return the current storage state with a short TTL cache.

        ir.attachment.create/write hits this on every call, so we avoid hammering
        ir.config_parameter. Cache is invalidated on every recompute.
        """
        dbname = self.env.cr.dbname
        cached = _state_cache.get(dbname)
        now = time.monotonic()
        if cached and cached[1] > now:
            return cached[0]
        state = self._read_state()
        _state_cache[dbname] = (state, now + _STATE_CACHE_TTL_SECONDS)
        return state

    # ------------------------------------------------------------------
    # Cron entry point
    # ------------------------------------------------------------------
    @api.model
    def _cron_check_storage(self):
        """ir.cron entry point: must not raise. Called every 30 min."""
        try:
            self.recompute_and_dispatch()
        except Exception:
            _logger.exception("IKERP storage: cron run failed; will retry next tick.")
