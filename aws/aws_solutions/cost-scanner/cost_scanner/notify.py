"""Slack webhook delivery.

Uses only the Python standard library (``urllib``) so it works in the AWS
Lambda Python runtime with no extra packages installed.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request

import boto3

log = logging.getLogger("cost_scanner.notify")

DEFAULT_TIMEOUT = 10


def post_to_slack(webhook_url: str, text: str, timeout: int = DEFAULT_TIMEOUT) -> bool:
    """POST a simple ``text`` payload to a Slack incoming-webhook URL.

    Returns True on HTTP 200, False otherwise.  Never raises.
    """
    if not webhook_url:
        log.error("post_to_slack called with an empty webhook URL")
        return False
    payload = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ok = resp.status == 200
            if not ok:
                log.error("Slack webhook returned HTTP %s: %s", resp.status, resp.read()[:200])
            return ok
    except Exception as exc:  # pragma: no cover - network / config errors
        log.error("Slack post failed: %s", exc)
        return False


def resolve_webhook(os_env: dict | None = None) -> str | None:
    """Resolve the Slack webhook URL.

    Priority:
      1. ``SLACK_WEBHOOK_URL`` environment variable.
      2. ``SLACK_WEBHOOK_SSM_PARAM`` -> read from SSM Parameter Store (SecureString).
    Returns None if neither is configured.
    """
    env = os_env if os_env is not None else os.environ
    url = env.get("SLACK_WEBHOOK_URL")
    if url:
        return url
    ssm_name = env.get("SLACK_WEBHOOK_SSM_PARAM")
    if ssm_name:
        try:
            ssm = boto3.client("ssm", region_name=env.get("AWS_REGION", "us-east-2"))
            url = ssm.get_parameter(Name=ssm_name, WithDecryption=True)["Parameter"]["Value"]
            log.info("Loaded Slack webhook from SSM parameter %s", ssm_name)
            return url
        except Exception as exc:
            log.error("Could not load Slack webhook from SSM %r: %s", ssm_name, exc)
            return None
    return None
