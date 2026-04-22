{
    "name": "IKERP User Limit",
    "version": "19.0.1.0.0",
    "summary": "Enforces a signed per-tenant internal-user cap for the IKERP SaaS platform.",
    "description": """
IKERP User Limit
================
Server-side enforcement of the internal-user cap defined by the tenant's plan.
The cap is signed with HMAC-SHA256 using a secret held only by the orchestrator
(env var IKERP_SIGNING_SECRET), so tenant admins cannot raise it by editing
ir.config_parameter. The module is also protected against uninstallation by
tenant admins.
    """,
    "author": "IKERP",
    "website": "https://ikerp.com",
    "category": "Administration",
    "license": "LGPL-3",
    "depends": ["base"],
    "data": [],
    "installable": True,
    "application": False,
    "auto_install": False,
}
