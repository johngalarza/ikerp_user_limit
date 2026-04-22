# IKERP User Limit

Server-side enforcement of the internal-user cap for an IKERP SaaS tenant.

- Cap stored in `ir.config_parameter` (`ikerp.max_users`) + HMAC-SHA256 signature.
- Secret read from env var `IKERP_SIGNING_SECRET` (never from the DB).
- Enforced on `res.users.create`, reactivation, and portal→internal share flips.
- Superuser (`uid=1`) is exempt so the orchestrator can operate freely.
- Uninstall is blocked for all users except SUPERUSER_ID.
# ikerp_user_limit
