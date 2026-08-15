"""Aggregate a :class:`DiscoveredReport` into a cost :class:`Report`.

The discovery layer already attached a per-resource ``estimated_cost``
(uptime × on-demand hourly rate) and ``hourly_rate``.  This module rolls
those up into totals split by *owner* (me vs. the SA team vs. both) and by
*service*, computes the live **burn rate** (USD/hour right now), and emits a
few actionable "waste" notes.
"""

from __future__ import annotations

import logging
from collections import Counter

from .model import (
    Category,
    DiscoveredReport,
    Report,
    Ec2Instance,
    RdsInstance,
    EksCluster,
)

log = logging.getLogger("cost_scanner.cost")

# An instance running longer than this is flagged as a longer-lived concern.
_LONG_RUN_HOURS = 24.0


def _is_burning(res) -> bool:
    """True if the resource is currently accruing instance/control cost."""
    if isinstance(res, Ec2Instance):
        return res.state == "running"
    if isinstance(res, RdsInstance):
        return res.state == "available"
    if isinstance(res, EksCluster):
        return True  # control plane is always on
    return False


def _is_mine(cat: Category) -> bool:
    return cat in (Category.MINE, Category.BOTH)


def _is_sa(cat: Category) -> bool:
    return cat in (Category.SOLUTIONS_ARCHITECT, Category.BOTH)


def aggregate(discovered: DiscoveredReport, ce_actuals: dict | None = None) -> Report:
    """Build the final :class:`Report` from a discovered inventory."""
    rep = Report(discovered=discovered)
    compute = discovered.all_compute()  # EC2 + RDS + EKS instances/clusters

    # Mine / SA / Both counts (BOTH counted in each bucket).
    for res in compute:
        if _is_mine(res.category):
            rep.mine_count += 1
        if _is_sa(res.category):
            rep.sa_team_count += 1
        if res.category == Category.BOTH:
            rep.both_count += 1

    # Per-service + per-owner cost totals.  Cost only counts resources that
    # are currently burning money (running EC2 / available RDS / always-on
    # EKS control plane).  Stopped EC2 still accrues EBS storage, noted below.
    for res in compute:
        cost = res.estimated_cost or 0.0
        rate = res.hourly_rate or 0.0
        burning = _is_burning(res)
        active_cost = cost if burning else 0.0

        if isinstance(res, Ec2Instance):
            rep.ec2_estimated_cost += active_cost
        if isinstance(res, RdsInstance):
            rep.rds_estimated_cost += active_cost
        if isinstance(res, EksCluster):
            rep.eks_estimated_cost += active_cost

        if _is_mine(res.category):
            rep.mine_estimated_cost += active_cost
        if _is_sa(res.category):
            rep.sa_team_estimated_cost += active_cost

        rep.total_estimated_cost += active_cost
        if burning:
            rep.total_burn_rate += rate

    # Round money fields
    rep.mine_estimated_cost = round(rep.mine_estimated_cost, 2)
    rep.sa_team_estimated_cost = round(rep.sa_team_estimated_cost, 2)
    rep.total_estimated_cost = round(rep.total_estimated_cost, 2)
    rep.total_burn_rate = round(rep.total_burn_rate, 6)
    rep.ec2_estimated_cost = round(rep.ec2_estimated_cost, 2)
    rep.rds_estimated_cost = round(rep.rds_estimated_cost, 2)
    rep.eks_estimated_cost = round(rep.eks_estimated_cost, 2)

    if ce_actuals:
        rep.ce_mtd_cost = ce_actuals.get("mtd_cost")
        rep.ce_mtd_currency = ce_actuals.get("currency", "USD")

    _add_notes(rep, discovered, compute)
    return rep


def _add_notes(rep: Report, discovered: DiscoveredReport, compute) -> None:
    """Populate human-readable observations / waste flags."""
    notes: list[str] = []

    # Biggest burner
    burning = [r for r in compute if _is_burning(r) and (r.hourly_rate or 0) > 0]
    if burning:
        top = max(burning, key=lambda r: r.hourly_rate or 0)
        ident = getattr(top, "resource_id", "?")
        itype = (
            getattr(top, "instance_type", None)
            or getattr(top, "db_instance_class", None)
            or "eks-control-plane"
        )
        notes.append(
            f"Largest hourly burner: {ident} ({itype}) at ${(top.hourly_rate or 0):.4f}/h "
            f"-> ${(top.hourly_rate or 0) * 24:.2f}/day if left on."
        )

    # Long-running instances
    long_runners = [r for r in compute if (r.uptime_hours or 0) >= _LONG_RUN_HOURS]
    if long_runners:
        notes.append(
            f"{len(long_runners)} resource(s) have been running > {_LONG_RUN_HOURS / 24:.0f} day(s)."
        )
    else:
        notes.append("No owned always-on compute has been running > 1 day.")

    # Stopped-but-owned (EBS still billed)
    stopped = [
        r for r in discovered.ec2_instances if (r.state or "") not in ("running",)
    ]
    if stopped:
        notes.append(
            f"{len(stopped)} owned EC2 instance(s) are stopped (EBS storage may still be billed)."
        )

    # RDS owned vs total
    if not discovered.rds_instances:
        notes.append(
            "No RDS instances match your ownership tags. If you expected some, "
            "check that they carry a `creator=<you>` or `team=sa` tag."
        )

    # Lambda note
    if discovered.lambda_functions:
        notes.append(
            f"{len(discovered.lambda_functions)} owned Lambda function(s) are "
            "pay-per-invocation (no wall-clock charge); included for completeness only."
        )

    # Rate-source transparency
    sources = Counter(r.rate_source for r in compute if getattr(r, "rate_source", None))
    if sources:
        parts = ", ".join(f"{v} {k}" for k, v in sources.most_common())
        notes.append(
            "Rate provenance this run: " + parts
            + " (live=Price List API, fallback=hardcoded table, fixed=EKS control plane)."
        )

    rep.notes = notes
