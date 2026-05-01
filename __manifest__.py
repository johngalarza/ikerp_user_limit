{
    "name": "IKERP User Limit",
    "version": "19.0.1.1.0",
    "summary": "Signed per-tenant user cap and storage quota for the IKERP SaaS platform.",
    "description": """
IKERP User & Storage Limit
==========================
Server-side enforcement of two HMAC-signed per-tenant caps:

* **Internal users** (``ikerp.max_users``) — blocks ``res.users`` creation /
  reactivation / portal-to-internal flips above the plan cap.
* **Storage** (``ikerp.storage_limit_mb``) — recomputes DB + filestore usage
  every 30 min, drives an in-app banner, emails the tenant admin, alerts the
  IKERP backend on each upward state transition, and blocks ``ir.attachment``
  growth (create / data-bearing write) when the tenant is over quota.

The HMAC secret lives only in the container env (``IKERP_SIGNING_SECRET``), so
tenant admins with DB access cannot raise their own caps. Uninstall is blocked
for non-superusers.
    """,
    "author": "IKERP",
    "website": "https://ikerp.com",
    "category": "Administration",
    "license": "LGPL-3",
    "depends": ["base", "mail", "web"],
    "data": [
        "data/ir_cron.xml",
        "data/mail_template.xml",
    ],
    "assets": {
        "web.assets_backend": [
            "ikerp_user_limit/static/src/js/storage_banner.js",
            "ikerp_user_limit/static/src/xml/storage_banner.xml",
            "ikerp_user_limit/static/src/scss/storage_banner.scss",
        ],
    },
    "installable": True,
    "application": False,
    "auto_install": False,
}
