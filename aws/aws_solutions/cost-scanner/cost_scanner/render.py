"""Render a :class:`Report` as Markdown (for Obsidian) and compact text
(for Slack).

The renderers are deliberately pure functions: they take a ``Report`` and
return a string, so they can be unit-tested without AWS.
"""

from __future__ import annotations

from datetime import datetime
from typing import Iterable

from .cost import _is_burning
from .model import (
    Category,
    Ec2Instance,
    EksCluster,
    Report,
    RdsInstance,
)
from .owner import OwnershipRules

_USD = "USD"


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def _money(v: float | None) -> str:
    if v is None:
        return "—"
    return f"${v:,.2f}"


def _fmt_uptime(hours: float | None) -> str:
    if not hours and hours != 0:
        return "—"
    if hours < 1:
        return f"{hours*60:.0f}m"
    if hours < 48:
        return f"{hours:.1f}h"
    days = hours / 24.0
    if days < 14:
        return f"{days:.1f}d ({hours:.0f}h)"
    return f"{days:.0f}d ({hours:.0f}h)"


def _owner_label(cat: Category) -> str:
    return {
        Category.MINE: "you",
        Category.SOLUTIONS_ARCHITECT: "SA team",
        Category.BOTH: "you + SA",
    }.get(cat, "—")


def _state_badge(res) -> str:
    st = getattr(res, "state", None)
    if isinstance(res, Ec2Instance):
        return "🟢 running" if st == "running" else (f"⚪ {st}" if st else "—")
    if isinstance(res, RdsInstance):
        return "🟢 available" if st == "available" else (f"⚪ {st}" if st else "—")
    return "🟢 on"


# --------------------------------------------------------------------------- #
# Markdown (Obsidian)
# --------------------------------------------------------------------------- #
def _compute_table_rows(report: Report) -> list[dict]:
    rows = []
    for res in report.discovered.all_compute():
        ident = res.resource_id
        typ = getattr(res, "instance_type", None) or getattr(res, "db_instance_class", None) or "eks-control-plane"
        rows.append(
            {
                "resource": ident,
                "service": res.service,
                "owner": _owner_label(res.category),
                "type": typ,
                "state": _state_badge(res),
                "uptime": _fmt_uptime(getattr(res, "uptime_hours", None)),
                "rate": f"{_money(getattr(res, 'hourly_rate', None))}/h"
                if getattr(res, "hourly_rate", None)
                else "—",
                "cost": _money(getattr(res, "estimated_cost", None)),
                "src": getattr(res, "rate_source", "—") or "—",
            }
        )
    # sort biggest accumulated cost first
    rows.sort(
        key=lambda r: float(r["cost"].replace("$", "").replace(",", "") or 0.0)
        if r["cost"] != "—" else 0.0,
        reverse=True,
    )
    return rows


def render_markdown(report: Report, rules: OwnershipRules, profile: str = "sandbox") -> str:
    """Full Markdown report (suitable for an Obsidian daily note)."""
    d = report.discovered
    gen = d.generated_at.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    lines: list[str] = []
    lines.append(f"# AWS {profile.title()} Resource Tracking — Daily Cost Report")
    lines.append("")
    lines.append(f"_Generated {gen}_")
    lines.append("")
    lines.append(
        f"**Account:** `{d.account_id}`  ·  **Region:** `{d.region}`  ·  **Profile:** `{profile}`"
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    compute = d.all_compute()
    owned_running = [r for r in compute if _is_burning(r)]
    both = sum(1 for r in compute if r.category == Category.BOTH)
    mine_only = sum(1 for r in compute if r.category == Category.MINE)
    sa_only = sum(1 for r in compute if r.category == Category.SOLUTIONS_ARCHITECT)
    lines.append(
        f"- **Always-on compute currently running (owned):** {len(owned_running)} "
        f"resource(s) — {mine_only} yours, {sa_only} SA-team, {both} shared (you + SA)."
    )
    lines.append(
        f"- **Estimated accumulated cost** (uptime × on-demand rate): "
        f"**{_money(report.total_estimated_cost)}**"
    )
    lines.append(
        f"  - You: {_money(report.mine_estimated_cost)} · SA team: "
        f"{_money(report.sa_team_estimated_cost)} · *(shared resources counted once in the total)*"
    )
    lines.append(
        f"- **Current burn rate:** {_money(report.total_burn_rate)}/hour "
        f"(~{_money(report.total_burn_rate * 24)}/day)"
    )
    lines.append(
        f"- **Cost by service:** EC2 {_money(report.ec2_estimated_cost)} · "
        f"RDS {_money(report.rds_estimated_cost)} · "
        f"EKS control plane {_money(report.eks_estimated_cost)}"
    )
    if report.ce_mtd_cost is not None:
        lines.append(
            f"- **Cost Explorer (actual MTD, whole account):** "
            f"{_money(report.ce_mtd_cost)} *(cross-check reference — see Methodology)*"
        )
    n_lambda = len(d.lambda_functions)
    if n_lambda:
        lines.append(
            f"- **Owned Lambda functions:** {n_lambda} *(pay-per-invocation, no wall-clock charge)*"
        )
    n_other = len(d.other_resources)
    if n_other:
        lines.append(f"- **Other owned resources (tagged, non-compute):** {n_other} across "
                     f"{_distinct_services(owned_running, d.other_resources)} service(s).")
    lines.append("")

    # Always-on compute table
    lines.append("## Always-on compute (running now)")
    lines.append("")
    rows = _compute_table_rows(report)
    if rows:
        lines.append("| Resource | Service | Owner | Type | State | Uptime | Rate | Est. cost | Rate src |")
        lines.append("|---|---|---|---|---|---|---|---|---|")
        for r in rows:
            lines.append(
                f"| `{r['resource']}` | {r['service']} | {r['owner']} | {r['type']} | "
                f"{r['state']} | {r['uptime']} | {r['rate']} | {r['cost']} | {r['src']} |"
            )
    else:
        lines.append("_No owned always-on compute is currently running._")
    lines.append("")

    # Per-service detail sections
    _append_detail_table(lines, "## EC2 instances", d.ec2_instances)
    _append_detail_table(lines, "## RDS instances", d.rds_instances)
    _append_detail_table(lines, "## EKS clusters (control plane)", d.eks_clusters)
    _append_lambda_table(lines, "## Lambda functions", d.lambda_functions)
    _append_other_table(lines, "## Other owned resources", d.other_resources)

    # Notes / waste flags
    lines.append("## Notes & waste flags")
    lines.append("")
    for n in (report.notes or []):
        lines.append(f"- {n}")
    lines.append("")

    # Methodology
    lines.append("## Methodology")
    lines.append("")
    lines.append(
        "Ownership is determined by tags (configurable):"
    )
    lines.append(
        f"- **You** = any tag in `{','.join(rules.owner_tags)}` whose value is in "
        f"`{','.join(sorted(rules.my_values))}`. In this account that is the `creator=boyd` tag "
        "(auto-derived from `chris.boyd@poolside.ai`)."
    )
    lines.append(
        f"- **Solutions Architect team** = tag `{rules.team_tag}` in "
        f"`{','.join(sorted(rules.team_values))}`."
    )
    lines.append("")
    lines.append(
        "Costs are **estimates** for always-on compute (running EC2, available RDS, EKS "
        "control plane) using **uptime × on-demand hourly rate**:"
    )
    lines.append(
        "- EC2 / RDS rates come from the **AWS Price List API** (`pricing.get_products`) "
        "in this account's region; a small hardcoded **fallback table** is used if a rate "
        "cannot be resolved (flagged `fallback`)."
    )
    lines.append(
        "- EKS control-plane rate is a fixed $0.10/hour (`fixed`). EC2 instance-hour cost stops "
        "when an instance is *stopped* (EBS storage is not modelled)."
    )
    lines.append(
        "- The **Cost Explorer** figure is actual billed cost pulled monthly; per-tag breakdowns "
        "require *activated* cost-allocation tags (this account's `creator`/`team` tags are not "
        "activated for cost allocation, so that sub-breakdown is unavailable)."
    )
    lines.append("")
    lines.append("> This file is a machine-generated daily snapshot. See `aws_solutions/cost-scanner`.")
    lines.append("")
    return "\n".join(lines)


def _distinct_services(*collections) -> int:
    svcs = set()
    for col in collections:
        for r in col:
            svcs.add(r.service)
    return len(svcs)


def _append_detail_table(lines, title: str, resources):
    lines.append(title)
    lines.append("")
    if not resources:
        lines.append("_None._")
        lines.append("")
        return
    lines.append("| Resource | Owner | Type | State/Uptime | Est. cost | Rate src |")
    lines.append("|---|---|---|---|---|---|")
    for r in resources:
        if isinstance(r, Ec2Instance):
            meta = f"{_state_badge(r)} · {_fmt_uptime(r.uptime_hours)} · {_money(r.hourly_rate)}/h"
            typ = r.instance_type or "—"
            cost = _money(r.estimated_cost) if r.state == "running" else "— (stopped)"
        elif isinstance(r, RdsInstance):
            meta = f"{_state_badge(r)} · {_fmt_uptime(r.uptime_hours)} · {_money(r.hourly_rate)}/h"
            typ = f"{r.db_instance_class} ({'Multi-AZ' if r.multi_az else 'Single-AZ'})"
            cost = _money(r.estimated_cost) if r.state == "available" else "— (stopped)"
        else:  # EksCluster
            meta = f"{_state_badge(r)} · {_fmt_uptime(r.uptime_hours)} · {_money(r.hourly_rate)}/h"
            typ = f"EKS v{r.version or '?'} control-plane"
            cost = _money(r.estimated_cost)
        lines.append(
            f"| `{r.resource_id}` | {_owner_label(r.category)} | {typ} | {meta} | {cost} | {r.rate_source or '—'} |"
        )
    lines.append("")


def _append_lambda_table(lines, title: str, fns):
    lines.append(title)
    lines.append("")
    if not fns:
        lines.append("_None._")
        lines.append("")
        return
    lines.append("| Function | Owner | Runtime | Memory | Timeout | Code (MB) |")
    lines.append("|---|---|---|---|---|---|")
    for f in fns:
        lines.append(
            f"| `{f.resource_id}` | {_owner_label(f.category)} | {f.runtime or '—'} | "
            f"{f.memory_mb or '—'} MB | {f.timeout or '—'}s | {f.code_size_mb or '—'} |"
        )
    lines.append("")


def _append_other_table(lines, title: str, others):
    lines.append(title)
    lines.append("")
    if not others:
        lines.append("_None._")
        lines.append("")
        return
    lines.append("| Resource | Service | Owner |")
    lines.append("|---|---|---|")
    for r in others:
        lines.append(f"| `{r.resource_id}` | {r.service} | {_owner_label(r.category)} |")
    lines.append("")


# --------------------------------------------------------------------------- #
# Slack (compact)
# --------------------------------------------------------------------------- #
def render_slack(report: Report, profile: str = "sandbox", obsidian_path: str | None = None) -> str:
    """Compact, Slack-friendly summary of the report."""
    d = report.discovered
    gen = d.generated_at.strftime("%Y-%m-%d %H:%M")
    bits = [
        f"*{profile} AWS cost scan* · {gen}  (acct `{d.account_id}`, `{d.region}`)",
        f"• Owned always-on compute running: {len([r for r in d.all_compute() if _is_burning(r)])}",
        f"• Estimated accumulated cost: *{_money(report.total_estimated_cost)}* "
        f"(you {_money(report.mine_estimated_cost)} · SA {_money(report.sa_team_estimated_cost)})",
        f"• Burn rate: {_money(report.total_burn_rate)}/h (~{_money(report.total_burn_rate * 24)}/d)",
        f"• By service — EC2 {_money(report.ec2_estimated_cost)} · "
        f"RDS {_money(report.rds_estimated_cost)} · EKS {_money(report.eks_estimated_cost)}",
    ]
    if report.ce_mtd_cost is not None:
        bits.append(f"• CE actual MTD (whole account): {_money(report.ce_mtd_cost)}")
    # top 3 burners
    burners = sorted(
        [r for r in d.all_compute() if _is_burning(r) and (r.hourly_rate or 0) > 0],
        key=lambda r: r.hourly_rate or 0,
        reverse=True,
    )[:3]
    if burners:
        bits.append("• Top burners:")
        for b in burners:
            typ = getattr(b, "instance_type", None) or getattr(b, "db_instance_class", None) or "eks"
            bits.append(
                f"   `{b.resource_id}` ({typ}) {_money(b.hourly_rate)}/h · "
                f"up {_fmt_uptime(b.uptime_hours)} · est {_money(b.estimated_cost)} · {_owner_label(b.category)}"
            )
    if obsidian_path:
        bits.append(f"• Full report: `{obsidian_path}`")
    return "\n".join(bits)

