# -*- coding: utf-8 -*-
import logging

from odoo import _, models, SUPERUSER_ID
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)

PROTECTED_MODULE = "ikerp_user_limit"


class IrModuleModule(models.Model):
    _inherit = "ir.module.module"

    def _ikerp_check_protected(self):
        """
        Block any attempt by a non-superuser to uninstall the IKERP user-limit
        module. Only the orchestrator (which connects as SUPERUSER_ID over RPC)
        may perform this operation -- e.g. when decommissioning a tenant.
        """
        # env.su is True when we are inside sudo() OR when the current user is
        # the superuser. We key on uid explicitly so that a tenant admin who
        # has Settings access (and can thus implicitly call sudo via the web
        # client in some flows) still cannot escape -- the web client runs
        # user-initiated actions with env.uid = the logged-in user.
        if self.env.uid == SUPERUSER_ID:
            return
        for mod in self:
            if mod.name == PROTECTED_MODULE:
                _logger.warning(
                    "IKERP user-limit: uid=%s tried to uninstall %r; blocked.",
                    self.env.uid, PROTECTED_MODULE,
                )
                raise UserError(
                    _(
                        "El módulo %(mod)s no puede ser desinstalado. "
                        "Contacta a soporte si necesitas dar de baja la "
                        "instancia.",
                        mod=PROTECTED_MODULE,
                    )
                )

    def button_uninstall(self):
        self._ikerp_check_protected()
        return super().button_uninstall()

    def button_immediate_uninstall(self):
        self._ikerp_check_protected()
        return super().button_immediate_uninstall()

    def module_uninstall(self):
        # Last-line defense: this is the low-level method invoked by the
        # uninstall pipeline. Covers any future UI paths that might skip
        # the button_* wrappers.
        self._ikerp_check_protected()
        return super().module_uninstall()
