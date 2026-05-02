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
import subprocess
import time
from datetime import datetime, timezone

from odoo import api, models, tools

from .ikerp_security import (
    IkerpParamMissingError,
    IkerpSignatureError,
    set_signed_param,
    verify_signed_param,
)

_logger = logging.getLogger(__name__)

PARAM_LIMIT_MB = "ikerp.storage_limit_mb"
PARAM_USED_MB = "ikerp.storage_used_mb"
PARAM_STATE = "ikerp.storage_state"
PARAM_LAST_RUN_AT = "ikerp.storage_last_run_at"
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

# Cron runs every 30 min. Allow up to ~3 missed ticks before fail-closing the
# hot path, so transient cron blips (worker restart, long migration) don't
# falsely block tenants. A disabled or crashed cron crosses this in ~90 min.
STALENESS_BUDGET_SECONDS = 90 * 60
LAST_RUN_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Module-level cache for ir.attachment hot-path reads. Keyed by dbname so a
# single worker serving multiple DBs stays correct. Holds the verified state
# plus the persisted used/limit (in bytes) needed to project growth without
# re-walking the filestore on every attachment create.
_STATE_CACHE_TTL_SECONDS = 60
_state_cache = {}

# Per-process running total of attachment bytes added since the cached snapshot
# was taken. Lets a single worker estimate "where are we now" between cron ticks
# without an SQL roundtrip per file. Cross-worker drift is reconciled on the
# next snapshot refresh — the disk-walk recompute sees every worker's writes
# regardless of which one made them.
_pending_growth_bytes = {}


def _now_utc_iso():
    return datetime.now(timezone.utc).strftime(LAST_RUN_TIMESTAMP_FORMAT)


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
        # Prefer `du -sb` — orders of magnitude faster than os.walk on big
        # filestores (tens of thousands of files). Fall back to os.walk if du
        # is missing, slow, or the filesystem rejects it.
        try:
            proc = subprocess.run(
                ["du", "-sb", path],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout:
                return int(proc.stdout.split()[0])
            _logger.warning(
                "IKERP storage: du -sb %s returned %s; falling back to os.walk. stderr=%s",
                path, proc.returncode, proc.stderr[:200],
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, ValueError, OSError) as exc:
            _logger.warning(
                "IKERP storage: du failed (%s); falling back to os.walk for %s.",
                exc, path,
            )
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
        """Raw read of the persisted state, signature-agnostic.

        Used internally to compute prev_state for transition diffing. Hot-path
        gating must use _read_verified_state instead — that one fail-closes on
        tampering or cron staleness.
        """
        return self.env["ir.config_parameter"].sudo().get_param(PARAM_STATE) or STATE_OK

    def _read_verified_state(self):
        """Return the state to enforce, fail-closing on tampering or staleness.

        Decision tree:
            * limit param missing             -> STATE_OK (legacy/forward compat).
            * limit param sig invalid         -> STATE_BLOCKED.
            * limit OK, state sig invalid     -> STATE_BLOCKED.
            * limit OK, last_run_at sig bad   -> STATE_BLOCKED.
            * limit OK, last_run_at too old   -> STATE_BLOCKED (cron disabled/dead).
            * everything signed and fresh     -> the persisted state.

        Missing state/last_run_at when the limit is configured is treated as
        tampering: the cron is supposed to populate both on every tick, plus
        once on install/upgrade via the post-init hook.
        """
        try:
            verify_signed_param(self.env, PARAM_LIMIT_MB)
        except IkerpParamMissingError:
            return STATE_OK
        except IkerpSignatureError:
            return STATE_BLOCKED

        try:
            state = verify_signed_param(self.env, PARAM_STATE)
        except IkerpSignatureError:
            return STATE_BLOCKED
        if state not in STATE_RANK:
            _logger.error("IKERP storage: unknown signed state=%r; blocking.", state)
            return STATE_BLOCKED

        try:
            last_run_iso = verify_signed_param(self.env, PARAM_LAST_RUN_AT)
        except IkerpSignatureError:
            return STATE_BLOCKED
        try:
            last_run = datetime.strptime(
                last_run_iso, LAST_RUN_TIMESTAMP_FORMAT,
            ).replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            _logger.error(
                "IKERP storage: last_run_at=%r is not parseable; blocking.",
                last_run_iso,
            )
            return STATE_BLOCKED

        age = (datetime.now(timezone.utc) - last_run).total_seconds()
        if age > STALENESS_BUDGET_SECONDS:
            _logger.warning(
                "IKERP storage: last_run_at is stale (%.0fs > %ds); "
                "fail-closing to blocked. Cron disabled or stuck?",
                age, STALENESS_BUDGET_SECONDS,
            )
            return STATE_BLOCKED

        return state

    def _write_snapshot(self, state, used_mb, db_mb, filestore_mb):
        ICP = self.env["ir.config_parameter"].sudo()
        # State and last_run_at are HMAC-signed: editing either via debug breaks
        # the signature, and a stopped cron lets last_run_at age past the
        # staleness budget — both paths fail-close to blocked.
        set_signed_param(self.env, PARAM_STATE, state)
        set_signed_param(self.env, PARAM_LAST_RUN_AT, _now_utc_iso())
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
        dbname = self.env.cr.dbname
        _state_cache.pop(dbname, None)
        # Snapshot just changed (du -sb walked the disk and now reflects every
        # worker's writes), so this worker's pending-bytes estimate is stale.
        _pending_growth_bytes.pop(dbname, None)

    def _get_snapshot(self):
        """Return cached {state, used_bytes, limit_bytes} for the hot path.

        Refreshed on TTL expiry or invalidation. Uses the fail-closed verified
        read so tampering or cron staleness surfaces as STATE_BLOCKED within at
        most _STATE_CACHE_TTL_SECONDS. limit_bytes is 0 when the limit is
        unconfigured or invalid — callers must treat that as "skip projection"
        and rely on the verified state alone.
        """
        dbname = self.env.cr.dbname
        cached = _state_cache.get(dbname)
        now = time.monotonic()
        if cached and cached["expires_at"] > now:
            return cached
        ICP = self.env["ir.config_parameter"].sudo()
        limit_mb, status = self._get_signed_limit_mb()
        limit_bytes = limit_mb * 1024 * 1024 if status == "ok" and limit_mb else 0
        try:
            used_mb = int(ICP.get_param(PARAM_USED_MB) or 0)
        except (TypeError, ValueError):
            used_mb = 0
        snap = {
            "state": self._read_verified_state(),
            "used_bytes": used_mb * 1024 * 1024,
            "limit_bytes": limit_bytes,
            "expires_at": now + _STATE_CACHE_TTL_SECONDS,
        }
        _state_cache[dbname] = snap
        # Fresh snapshot already reflects every worker's writes, so reset the
        # per-worker estimate.
        _pending_growth_bytes[dbname] = 0
        return snap

    @api.model
    def _get_cached_state(self):
        """Return the current verified storage state with a short TTL cache."""
        return self._get_snapshot()["state"]

    @api.model
    def _check_attachment_growth(self, payload_bytes):
        """Project usage and decide whether this attachment growth must block.

        Returns True iff the caller should raise. Called from ir.attachment
        create/write before super(). Workflow:

            1. If cached state is already BLOCKED, block (existing behavior).
            2. Without a configured limit, skip projection — only the verified
               state gates writes.
            3. Otherwise project: persisted_used + per-worker pending + this
               payload. If the projection crosses a threshold above the cached
               state, run a synchronous recompute_and_dispatch (du -sb walks
               the disk, refreshes persisted snapshot, dispatches alerts).
            4. After recompute, re-project against the fresh persisted value.
               Block iff the projection still lands at BLOCKED — the new file
               isn't on disk yet, so we can't trust the recomputed state alone
               for the gate decision.
            5. If we did not trigger a recompute, accumulate pending bytes so
               subsequent calls see this file's contribution.
        """
        snap = self._get_snapshot()
        if snap["state"] == STATE_BLOCKED:
            return True
        if snap["limit_bytes"] <= 0:
            return False
        dbname = self.env.cr.dbname
        pending = _pending_growth_bytes.get(dbname, 0)
        projected = snap["used_bytes"] + pending + payload_bytes
        projected_state = self._state_for(projected / float(snap["limit_bytes"]))
        if STATE_RANK[projected_state] > STATE_RANK[snap["state"]]:
            self.recompute_and_dispatch()
            snap = self._get_snapshot()
            if snap["state"] == STATE_BLOCKED:
                return True
            if snap["limit_bytes"] <= 0:
                return False
            # Re-project against fresh persisted; pending was reset by the
            # invalidation triggered inside recompute_and_dispatch.
            projected = snap["used_bytes"] + payload_bytes
            if self._state_for(projected / float(snap["limit_bytes"])) == STATE_BLOCKED:
                return True
            _pending_growth_bytes[dbname] = payload_bytes
            return False
        _pending_growth_bytes[dbname] = pending + payload_bytes
        return False

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
