"""Cost Explorer cross-check.

The per-resource estimate (``uptime × on-demand rate``) tells you how much an
individual *owned* resource has cost so far.  Cost Explorer tells you how
much the account **actually** spent, which is a useful sanity check.

All of this is **best-effort**: many accounts don't activate cost-allocation
tags, and CE data has ~24h latency.  If anything fails we return an empty /
partial result so the rest of the report still renders.
"""

from __future__ import annotations

import logging
from datetime import date, timedelta

import boto3

log = logging.getLogger("cost_scanner.ce")


def _month_range() -> tuple[str, str]:
    """Return (start, end) ISO dates spanning the current month-to-date."""
    today = date.today()
    start = today.replace(day=1)
    end = today + timedelta(days=1)  # CE requires End > Start; include today
    return start.isoformat(), end.isoformat()


def get_mtd_actuals(
    ce_client=None,
    owner_values: list[str] | None = None,
    team_values: list[str] | None = None,
) -> dict:
    """Return best-effort Cost-Explorer actuals for the month-to-date.

    Returns a dict with::

        mtd_cost        : float | None   -- total account MTD unblended cost
        currency        : str            -- e.g. "USD"
        period_start    : str
        period_end      : str
        by_creator      : dict           -- creator tag value -> usd (best effort)
        by_team         : dict           -- team tag value -> usd (best effort)
        owner_actual    : float | None   -- sum of costs tagged with your creator values
        team_actual     : float | None   -- sum of costs tagged with SA-team values
        error           : str | None     -- set if the total query failed
    """
    if ce_client is None:
        ce_client = boto3.client("ce")

    start, end = _month_range()
    out = {
        "mtd_cost": None,
        "currency": "USD",
        "period_start": start,
        "period_end": end,
        "by_creator": {},
        "by_team": {},
        "owner_actual": None,
        "team_actual": None,
        "error": None,
    }

    # 1) Total account MTD (no tag filter) -- broad sanity check.
    try:
        resp = ce_client.get_cost_and_usage(
            TimePeriod={"Start": start, "End": end},
            Granularity="MONTHLY",
            Metrics=["UNBLENDED_COST", "AMORTIZED_COST"],
        )
        results = resp.get("ResultsByTime", [])
        if results:
            total = results[0].get("Total", {})
            ub = total.get("UNBLENDED_COST") or total.get("AmortizedCost")
            if ub:
                out["mtd_cost"] = round(float(ub["Amount"]), 2)
                out["currency"] = ub.get("Unit") or "USD"
    except Exception as exc:
        log.warning("CE total MTD failed: %s", exc)
        out["error"] = f"CE total: {exc}"

    # 2) Break down by creator tag (needs the tag activated for cost alloc).
    by_creator = _group_by_tag(ce_client, start, end, "creator")
    out["by_creator"] = by_creator
    if owner_values:
        want = {x.lower() for x in owner_values}
        out["owner_actual"] = round(
            sum(v for k, v in by_creator.items() if k.lower() in want), 2
        )

    # 3) Break down by team tag (best effort).
    by_team = _group_by_tag(ce_client, start, end, "team")
    out["by_team"] = by_team
    if team_values:
        want = {x.lower() for x in team_values}
        out["team_actual"] = round(
            sum(v for k, v in by_team.items() if k.lower() in want), 2
        )

    return out


def _group_by_tag(ce_client, start: str, end: str, tag_key: str) -> dict:
    """Group MTD costs by a single cost-allocation tag -> {value: usd}."""
    out: dict[str, float] = {}
    try:
        resp = ce_client.get_cost_and_usage(
            TimePeriod={"Start": start, "End": end},
            Granularity="MONTHLY",
            Metrics=["UNBLENDED_COST"],
            GroupBy=[{"Type": "TAG", "Key": f"resourceTag/{tag_key}"}],
        )
        for period in resp.get("ResultsByTime", []):
            for g in period.get("Groups", []):
                # key looks like "resourceTag/creator$boyd"
                key = g["Keys"][0]
                name = key.split("$", 1)[-1] if "$" in key else key
                amt = float(g.get("Metrics", {}).get("UNBLENDED_COST", {}).get("Amount", 0))
                out[name] = round(out.get(name, 0.0) + amt, 2)
    except Exception as exc:
        log.warning("CE group-by tag %r failed: %s", tag_key, exc)
    return out
