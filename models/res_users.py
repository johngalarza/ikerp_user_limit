# -*- coding: utf-8 -*-
import hashlib
import hmac
import logging
import os

from odoo import _, api, models, SUPERUSER_ID
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)

# ir.config_parameter keys
PARAM_MAX_USERS = "ikerp.max_users"
PARAM_MAX_USERS_SIG = "ikerp.max_users_sig"
PARAM_PLAN_CODE = "ikerp.plan_code"

# Environment variable holding the HMAC secret. Deliberately NOT stored in
# ir.config_parameter: the tenant admin has DB access to that table, but not
# to the container environment.
ENV_SIGNING_SECRET = "IKERP_SIGNING_SECRET"


class ResUsers(models.Model):
    _inherit = "res.users"

    # ------------------------------------------------------------------
    # Signature / license helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _ikerp_get_secret():
        """Return the HMAC secret from the environment, or None if unset."""
        secret = os.environ.get(ENV_SIGNING_SECRET)
        if not secret:
            return None
        # Always encode as bytes for hmac
        return secret.encode("utf-8")

    @staticmethod
    def _ikerp_compute_signature(raw_value, secret_bytes):
        """HMAC-SHA256 hex of the raw string `raw_value` using `secret_bytes`."""
        return hmac.new(
            secret_bytes, raw_value.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def _ikerp_get_validated_limit(self):
        """
        Return the validated max-internal-users cap as an int.

        Raises UserError (fail-closed) if:
        - the env secret is missing,
        - the cap parameter is missing or not an int,
        - the signature is missing or does not match.
        """
        secret = self._ikerp_get_secret()
        if not secret:
            _logger.error(
                "IKERP user-limit: env var %s is not set; blocking user "
                "creation until the orchestrator configures it.",
                ENV_SIGNING_SECRET,
            )
            raise UserError(
                _("La configuración de licencia es inválida. Contacta a soporte.")
            )

        ICP = self.env["ir.config_parameter"].sudo()
        raw_limit = ICP.get_param(PARAM_MAX_USERS)
        stored_sig = ICP.get_param(PARAM_MAX_USERS_SIG)

        if not raw_limit or not stored_sig:
            _logger.error(
                "IKERP user-limit: missing parameter(s) max_users=%r sig=%r",
                raw_limit, stored_sig,
            )
            raise UserError(
                _("La configuración de licencia es inválida. Contacta a soporte.")
            )

        expected_sig = self._ikerp_compute_signature(raw_limit, secret)
        if not hmac.compare_digest(expected_sig, stored_sig):
            _logger.error(
                "IKERP user-limit: HMAC mismatch for max_users=%r "
                "(possible tampering with ir.config_parameter).",
                raw_limit,
            )
            raise UserError(
                _("La configuración de licencia es inválida. Contacta a soporte.")
            )

        try:
            limit = int(raw_limit)
        except (TypeError, ValueError):
            _logger.error(
                "IKERP user-limit: max_users=%r is not a valid integer.",
                raw_limit,
            )
            raise UserError(
                _("La configuración de licencia es inválida. Contacta a soporte.")
            )

        if limit < 0:
            _logger.error("IKERP user-limit: negative limit %s", limit)
            raise UserError(
                _("La configuración de licencia es inválida. Contacta a soporte.")
            )

        return limit

    def _ikerp_count_internal_users(self, exclude_ids=None):
        """
        Count currently active internal users (share=False, active=True).
        `exclude_ids` lets us discount users whose status is about to change
        in the same transaction (e.g. being archived by the same write).
        """
        domain = [("share", "=", False), ("active", "=", True)]
        if exclude_ids:
            domain.append(("id", "not in", list(exclude_ids)))
        # active_test=False is not strictly needed since we filter active
        # explicitly, but it makes intent clear.
        return self.env["res.users"].with_context(active_test=False).search_count(domain)

    def _ikerp_is_bypass(self):
        """
        Superuser is exempt so the orchestrator (calling as uid=1 over RPC)
        can perform maintenance, run upgrades, etc. without tripping the cap.
        """
        return self.env.uid == SUPERUSER_ID or self.env.su

    def _ikerp_enforce(self, new_internal_count):
        """
        Raise UserError if `new_internal_count` would exceed the validated cap.
        """
        limit = self._ikerp_get_validated_limit()
        if new_internal_count > limit:
            plan = self.env["ir.config_parameter"].sudo().get_param(
                PARAM_PLAN_CODE, default=""
            )
            plan_suffix = " (%s)" % plan if plan else ""
            _logger.warning(
                "IKERP user-limit: attempt to exceed cap. plan=%r limit=%s "
                "new_count=%s actor_uid=%s",
                plan, limit, new_internal_count, self.env.uid,
            )
            raise UserError(
                _(
                    "Has alcanzado el límite de usuarios internos de tu plan%(plan)s.\n"
                    "Límite: %(limit)s. Si necesitas más usuarios, actualiza tu plan.",
                    plan=plan_suffix,
                    limit=limit,
                )
            )

    # ------------------------------------------------------------------
    # CRUD overrides
    # ------------------------------------------------------------------
    @api.model_create_multi
    def create(self, vals_list):
        if self._ikerp_is_bypass():
            return super().create(vals_list)

        # Count how many of the new users would be internal and active.
        # Defaults in Odoo: active=True, share=False unless set otherwise.
        new_internal = 0
        for vals in vals_list:
            active = vals.get("active", True)
            share = vals.get("share", False)
            if active and not share:
                new_internal += 1

        if new_internal:
            current = self._ikerp_count_internal_users()
            self._ikerp_enforce(current + new_internal)

        return super().create(vals_list)

    def write(self, vals):
        if self._ikerp_is_bypass():
            return super().write(vals)

        # We only need to validate if the write could ADD internal users:
        #   - reactivation: active True
        #   - share flip:   share False (portal -> internal)
        activating = vals.get("active") is True
        internalizing = vals.get("share") is False and "share" in vals

        if not (activating or internalizing):
            return super().write(vals)

        # Among the records in self, figure out which ones would transition
        # INTO the internal-active set as a result of this write.
        # A user ends up as "internal-active" after the write iff:
        #   final_active == True AND final_share == False
        # We compute the delta: final internal-active that weren't before.
        transitioning = 0
        for user in self.with_context(active_test=False):
            was_internal_active = user.active and not user.share
            final_active = vals["active"] if "active" in vals else user.active
            final_share = vals["share"] if "share" in vals else user.share
            will_be_internal_active = bool(final_active) and not bool(final_share)
            if will_be_internal_active and not was_internal_active:
                transitioning += 1

        if transitioning:
            # Exclude the records being written from the base count so we
            # don't double-count them (their pre-write state is already
            # accounted for in `transitioning`).
            current = self._ikerp_count_internal_users(exclude_ids=self.ids)
            self._ikerp_enforce(current + transitioning)

        return super().write(vals)
