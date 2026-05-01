# -*- coding: utf-8 -*-
"""HMAC-signed ir.config_parameter helpers for the IKERP SaaS license layer.

The HMAC secret lives only in the container env (IKERP_SIGNING_SECRET) so that a
tenant admin with DB access cannot forge or raise their own caps. Each signed
parameter X has a sibling parameter X_sig holding HMAC_SHA256(secret, str(X)).
"""
import hashlib
import hmac
import logging
import os

_logger = logging.getLogger(__name__)

ENV_SIGNING_SECRET = "IKERP_SIGNING_SECRET"


class IkerpSignatureError(Exception):
    """Base class for signed-param validation failures."""


class IkerpParamMissingError(IkerpSignatureError):
    """The signed parameter itself is absent from ir.config_parameter.

    Callers that want forward-compat behavior (e.g. storage rollout to old
    tenants) treat this as "not configured yet" instead of tampering.
    """


class IkerpSignatureInvalidError(IkerpSignatureError):
    """The secret env var is missing, the signature is missing, or HMAC mismatch."""


def get_secret():
    secret = os.environ.get(ENV_SIGNING_SECRET)
    return secret.encode("utf-8") if secret else None


def compute_signature(raw_value, secret_bytes):
    return hmac.new(
        secret_bytes, raw_value.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def verify_signed_param(env, param_name, sig_param_name=None):
    """Read and HMAC-verify a signed ir.config_parameter.

    Returns the raw string value on success. Raises:
        IkerpParamMissingError   - the value parameter is absent.
        IkerpSignatureInvalidError - secret env missing, sig absent, or HMAC mismatch.
    """
    sig_param_name = sig_param_name or (param_name + "_sig")
    ICP = env["ir.config_parameter"].sudo()
    raw_value = ICP.get_param(param_name)
    stored_sig = ICP.get_param(sig_param_name)

    if not raw_value:
        # Compat case: callers can decide whether absence means "block" or
        # "not configured yet" (e.g. legacy tenants pre-rollout).
        raise IkerpParamMissingError(param_name)

    secret = get_secret()
    if not secret:
        _logger.error(
            "IKERP signed-param: env var %s is not set; cannot verify %s.",
            ENV_SIGNING_SECRET, param_name,
        )
        raise IkerpSignatureInvalidError("missing secret")

    if not stored_sig:
        _logger.error(
            "IKERP signed-param: %s is present but %s is missing.",
            param_name, sig_param_name,
        )
        raise IkerpSignatureInvalidError("missing signature")

    expected_sig = compute_signature(raw_value, secret)
    if not hmac.compare_digest(expected_sig, stored_sig):
        _logger.error(
            "IKERP signed-param: HMAC mismatch for %s=%r (possible tampering).",
            param_name, raw_value,
        )
        raise IkerpSignatureInvalidError("hmac mismatch")

    return raw_value
