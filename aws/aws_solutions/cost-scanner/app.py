"""AWS Lambda entry point.

Deployed into the sandbox account (execution role) and triggered every
morning by an EventBridge ``cron`` rule, this handler runs the shared
cost-scanner core and posts a compact summary to Slack.

Environment variables (all read by the core library):

    PROFILE            AWS profile / account to scan (informational; the
                       Lambda always scans its own account via its exec role)
    ENABLE_CE          set to "1" to include the Cost-Explorer cross-check
                       (default: off -- CE is slow and can throttle)
    SLACK_WEBHOOK_URL  or  SLACK_WEBHOOK_SSM_PARAM=...  -- where to post

The handler is also directly invokable: ``lambda.invoke(FunctionName=...)``
returns the same summary on the invocation response.
"""

from __future__ import annotations

import json
import logging
import os

import boto3

from cost_scanner.ce import get_mtd_actuals
from cost_scanner.cost import aggregate
from cost_scanner.discovery import discover
from cost_scanner.owner import OwnershipRules
from cost_scanner.rates import Rates
from cost_scanner.render import render_slack
from cost_scanner.notify import resolve_webhook, post_to_slack

log = logging.getLogger("cost_scanner.app")

PROFILE = os.getenv("PROFILE", "sandbox")
ENABLE_CE = os.getenv("ENABLE_CE", "1") == "1"


def handler(event=None, context=None) -> dict:
    """Scheduled Lambda entry point."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    session = boto3.Session()  # uses the execution role
    region = session.region_name or "us-east-2"
    rules = OwnershipRules()
    rates = Rates(region)

    log.info("Starting daily cost scan of %s (%s)", PROFILE, region)
    rep = discover(rules, rates, session=session)

    ce_actuals = None
    if ENABLE_CE:
        try:
            ce_actuals = get_mtd_actuals(
                ce_client=session.client("ce"),
                owner_values=sorted(rules.my_values),
                team_values=sorted(rules.team_values),
            )
        except Exception as exc:
            log.warning("Cost Explorer unavailable: %s", exc)

    report = aggregate(rep, ce_actuals)
    slack_text = render_slack(report, profile=PROFILE)

    webhook = resolve_webhook()
    sent = False
    if webhook:
        sent = post_to_slack(webhook, slack_text)
        log.info("Slack summary %s", "sent" if sent else "FAILED")
    else:
        log.warning("No Slack webhook configured; emitting summary to logs only.")
        log.info("Slack summary:\n%s", slack_text)

    return {
        "statusCode": 200 if (sent or not webhook) else 502,
        "profile": PROFILE,
        "region": region,
        "account_id": report.discovered.account_id,
        "generated_at": report.discovered.generated_at.isoformat(),
        "summary": {
            "total_estimated_cost": report.total_estimated_cost,
            "mine_estimated_cost": report.mine_estimated_cost,
            "sa_team_estimated_cost": report.sa_team_estimated_cost,
            "total_burn_rate": report.total_burn_rate,
            "ec2": report.ec2_estimated_cost,
            "rds": report.rds_estimated_cost,
            "eks": report.eks_estimated_cost,
            "ce_mtd_cost": report.ce_mtd_cost,
            "slack_sent": sent,
        },
        "slack_text": slack_text,
    }


# When invoked without a Lambda context (e.g. ``python app.py``), run once
# and print the summary so the same code is testable locally.
if __name__ == "__main__":
    print(json.dumps(handler(), indent=2, default=str))
