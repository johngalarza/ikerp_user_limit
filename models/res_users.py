# -*- coding: utf-8 -*-
import logging

from odoo import _, api, models, SUPERUSER_ID
from odoo.exceptions import UserError

from .ikerp_security import (
    IkerpSignatureError,
    verify_signed_param,
)

_logger = logging.getLogger(__name__)

# ir.config_parameter keys
PARAM_MAX_USERS = "ikerp.max_users"
PARAM_PLAN_CODE = "ikerp.plan_code"


class ResUsers(models.Model):
    _inherit = "res.users"

    def _ikerp_get_validated_limit(self):
        """Return the validated max-internal-users cap as an int.

        Raises UserError (fail-closed) on any signature/parameter problem.
        """
        try:
            raw_limit = verify_signed_param(self.env, PARAM_MAX_USERS)
        except IkerpSignatureError:
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
        """Count currently active internal users (share=False, active=True).

        `exclude_ids` lets us discount users whose status is about to change in
        the same transaction (e.g. being archived by the same write).
        """
        domain = [("share", "=", False), ("active", "=", True)]
        if exclude_ids:
            domain.append(("id", "not in", list(exclude_ids)))
        return self.env["res.users"].with_context(active_test=False).search_count(domain)

    def _ikerp_is_bypass(self):
        """Superuser is exempt so the orchestrator (calling as uid=1 over RPC)
        can perform maintenance, run upgrades, etc. without tripping the cap.
        """
        return self.env.uid == SUPERUSER_ID or self.env.su

    def _ikerp_enforce(self, new_internal_count):
        """Raise UserError if `new_internal_count` would exceed the validated cap."""
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

    @api.model_create_multi
    def create(self, vals_list):
        if self._ikerp_is_bypass():
            return super().create(vals_list)

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

        activating = vals.get("active") is True
        internalizing = vals.get("share") is False and "share" in vals

        if not (activating or internalizing):
            return super().write(vals)

        transitioning = 0
        for user in self.with_context(active_test=False):
            was_internal_active = user.active and not user.share
            final_active = vals["active"] if "active" in vals else user.active
            final_share = vals["share"] if "share" in vals else user.share
            will_be_internal_active = bool(final_active) and not bool(final_share)
            if will_be_internal_active and not was_internal_active:
                transitioning += 1

        if transitioning:
            current = self._ikerp_count_internal_users(exclude_ids=self.ids)
            self._ikerp_enforce(current + transitioning)

        return super().write(vals)
