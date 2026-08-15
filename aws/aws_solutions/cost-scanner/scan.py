#!/usr/bin/env python3
"""Local CLI for the AWS cost scanner.

Scans a profile/account for resources owned by you or the Solutions
Architect team, estimates how much running compute has cost so far, and
writes a dated Markdown report into your Obsidian vault.  Optionally also
posts a compact summary to Slack.

Examples
--------
# Default: scan sandbox, write to ~/Documents/Devault/AWS Sandbox Resource tracking
AWS_PROFILE=sandbox python3 scan.py

# Specify a different profile / region
python3 scan.py --profile platform --region us-east-1

# Also post a summary to Slack (needs SLACK_WEBHOOK_URL)
python3 scan.py --slack

# Dry-run: print the report instead of writing a file
python3 scan.py --print
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

import boto3

# Allow running both as `python scan.py` from the repo root and as an
# installed console script.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cost_scanner.ce import get_mtd_actuals
from cost_scanner.cost import aggregate
from cost_scanner.discovery import discover
from cost_scanner.owner import OwnershipRules
from cost_scanner.rates import Rates
from cost_scanner.render import render_markdown, render_slack

DEFAULT_OBSIDIAN_DIR = os.path.expanduser(
    "~/Documents/Devault/AWS Sandbox Resource tracking"
)
DEFAULT_PROFILE = os.getenv("AWS_PROFILE", "sandbox")
DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-2")

log = logging.getLogger("cost_scanner.scan")


def _ensure_credentials(session: boto3.Session, profile: str) -> None:
    """Pre-flight check: fail fast with an actionable message if the AWS
    SSO/session credentials are expired.

    The scheduled 10am run has no TTY, so a helpful hint in the log beats a
    stack trace in ``cost-scanner.err.log``.
    """
    try:
        session.client("sts").get_caller_identity()
    except Exception as exc:
        name = type(exc).__name__
        code = ""
        if getattr(exc, "response", None):
            code = exc.response.get("Error", {}).get("Code", "")
        # botocore raises a variety of auth/credential exceptions
        # (NoCredentialsError, UnauthorizedSSOTokenError, ClientError with
        # ExpiredToken/InvalidClientTokenId codes).  Name- or code-match them
        # so the 10am scheduled run leaves a helpful log line instead of a
        # stack trace when your SSO session needs refreshing.
        friendly = any(tok in name for tok in ("Credential", "Token", "SSO", "Auth")) or code in (
            "ExpiredToken", "ExpiredTokenException",
            "InvalidClientTokenId", "UnrecognizedClientException",
        )
        if friendly:
            log.error(
                "AWS credentials for profile %r are expired/invalid (%.200s). "
                "Refresh them, then let the next scheduled run proceed:  "
                "aws sso login --profile %s",
                profile, exc, profile,
            )
            raise SystemExit(2) from exc
        raise  # any other error should surface normally


def build_session(profile: str, region: str) -> boto3.Session:
    return boto3.Session(profile_name=profile or None, region_name=region)


def run(profile: str, region: str, enable_ce: bool, slack_webhook: str | None,
        obsidian_dir: str | None, write_obsidian: bool, also_print: bool) -> str:
    session = build_session(profile, region)
    _ensure_credentials(session, profile)
    rules = OwnershipRules()
    rates = Rates(region)

    # Resolve "you" / "SA team" value lists for the CE cross-check.
    owner_values = sorted(rules.my_values)
    team_values = sorted(rules.team_values)

    rep = discover(rules, rates, session=session)
    ce_actuals = get_mtd_actuals(
        ce_client=session.client("ce"),
        owner_values=owner_values,
        team_values=team_values,
    ) if enable_ce else None

    report = aggregate(rep, ce_actuals)
    markdown = render_markdown(report, rules, profile=profile)

    obsidian_path = None
    if write_obsidian or obsidian_dir:
        out_dir = Path(obsidian_dir or DEFAULT_OBSIDIAN_DIR)
        out_dir.mkdir(parents=True, exist_ok=True)
        date_str = report.discovered.generated_at.strftime("%Y-%m-%d")
        obsidian_path = out_dir / f"{date_str} AWS Cost Report.md"
        obsidian_path.write_text(markdown, encoding="utf-8")
        log.info("Wrote report: %s", obsidian_path)

    if also_print or not (write_obsidian or obsidian_dir):
        print(markdown)

    if slack_webhook:
        from cost_scanner.notify import post_to_slack
        slack_text = render_slack(report, profile=profile, obsidian_path=str(obsidian_path) if obsidian_path else None)
        ok = post_to_slack(slack_webhook, slack_text)
        log.info("Slack post %s", "succeeded" if ok else "FAILED")

    return str(obsidian_path) if obsidian_path else markdown


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Scan AWS for owned-running-compute cost waste.")
    p.add_argument("--profile", default=DEFAULT_PROFILE, help="AWS profile to scan")
    p.add_argument("--region", default=DEFAULT_REGION, help="AWS region")
    p.add_argument("--no-ce", action="store_true", help="Skip Cost Explorer (faster)")
    p.add_argument("--no-obsidian", action="store_true", help="Don't write the Markdown report")
    p.add_argument("--obsidian-dir", default=None, help="Override Obsidian output folder")
    p.add_argument("--print", action="store_true", help="Print report to stdout")
    p.add_argument("--slack", action="store_true", help="Also post a summary to Slack (SLACK_WEBHOOK_URL)")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    webhook = os.getenv("SLACK_WEBHOOK_URL") if args.slack else None
    if args.slack and not webhook:
        log.error("--slack requested but SLACK_WEBHOOK_URL is not set")

    try:
        run(
            profile=args.profile,
            region=args.region,
            enable_ce=not args.no_ce,
            slack_webhook=webhook,
            obsidian_dir=None if args.no_obsidian else args.obsidian_dir,
            write_obsidian=not args.no_obsidian,
            also_print=args.print,
        )
    except Exception:
        log.exception("scan failed")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
