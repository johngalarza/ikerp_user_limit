# IKERP User Limit

Server-side enforcement of per-tenant caps on an IKERP SaaS instance.
Both caps are signed with HMAC-SHA256 using a secret held only by the
orchestrator (`IKERP_SIGNING_SECRET`), so tenant admins with DB access cannot
raise them by editing `ir.config_parameter`.

## What it enforces

### Internal-user cap (`v1.0`+)

- Cap stored in `ir.config_parameter` (`ikerp.max_users`) + HMAC signature.
- Enforced on `res.users.create`, reactivation, and portal→internal flips.
- Superuser (`uid=1`) is exempt so the orchestrator can operate freely.
- Uninstall is blocked for all users except `SUPERUSER_ID`.

### Storage quota (`v1.1`+)

- Limit stored in `ir.config_parameter` (`ikerp.storage_limit_mb`) + HMAC.
- A 30-min cron (`ikerp_user_limit.cron_check_storage`) recomputes
  `db_bytes + filestore_bytes`, writes `ikerp.storage_used_mb` and
  `ikerp.storage_state` (`ok` / `warning` / `critical` / `blocked`).
- Thresholds: `≥0.80` warning, `≥0.95` critical, `≥1.00` blocked.
- On each upward transition: POST to `IKERP_ALERTS_URL` with bearer
  `IKERP_METRICS_TOKEN` + `X-Instance-Id: IKERP_INSTANCE_ID`. Critical/blocked
  also email the tenant admin (`ikerp.admin_email` config param, fallback
  `base.user_admin`).
- When `state == blocked`, `ir.attachment.create()` and growth-bearing
  `write({ raw / datas / ... })` raise `UserError`. `unlink()` stays open so
  the user can free space.
- Backend alerts and emails fail soft — never derail the cron.
- An in-app banner (loaded via `web.assets_backend`) polls
  `/ikerp/storage/state` and shows a non-dismissible warning/critical/blocked
  message in the backend header.

## Compatibility

If `ikerp.storage_limit_mb` is **not present**, the module stays in `ok` and
logs `storage limit not configured` — this lets pre-rollout tenants run
unaffected. A present-but-unsigned (or tampered) limit is treated as
**blocked** (fail-closed, same as the user cap).

## Environment variables

| Var | Purpose |
| --- | --- |
| `IKERP_SIGNING_SECRET`   | HMAC key for both signed params. **Required.** |
| `IKERP_ALERTS_URL`       | Backend endpoint for storage alerts. Optional — if empty, alerts are skipped. |
| `IKERP_METRICS_TOKEN`    | Bearer token for the alerts POST (reused from the metrics pipeline). |
| `IKERP_INSTANCE_ID`      | Sent as `X-Instance-Id` on alerts. |

## Upgrading from v1.0

After pulling the new tag, **update `IKERP_USER_LIMIT_REF` in your backend**
to point at the new tag (e.g. `v1.1.0`) so freshly provisioned tenants get
the storage logic. Existing tenants get it the next time the orchestrator
syncs the addon.

## Tests

```bash
odoo --test-enable -i ikerp_user_limit --stop-after-init
```

Covers HMAC validation (good/tampered/missing), DB+filestore measurement,
state-transition POST exactness, and `ir.attachment` blocking semantics.
