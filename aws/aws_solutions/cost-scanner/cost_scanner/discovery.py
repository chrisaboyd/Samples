"""Resource discovery for the cost scanner.

Two sources of truth are combined:

1. The **Resource Groups Tagging API** gives a single account-wide list of
   tagged resources (ARN + tags) across (almost) every service.  We use it
   to classify every resource as ``mine``, ``solutions-architect`` or
   ``unclassified`` and to count the non-compute resources we own.

2. **Per-service describe calls** (EC2 / RDS / EKS / Lambda) give the
   wall-clock timestamps needed to compute uptime -- the tagging API does
   not expose ``LaunchTime`` / ``InstanceCreateTime`` etc.  We intersect
   their results with the ownership tags we already know about.

Only resources whose tags classify them as ``mine`` or ``solutions-architect``
(or both) are returned; unclassified resources are deliberately ignored so
the daily report stays focused on *your* spend.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import boto3

from .model import (
    Category,
    DiscoveredReport,
    Ec2Instance,
    EksCluster,
    LambdaFunction,
    OtherResource,
    RdsInstance,
)
from .owner import OwnershipRules
from .rates import Rates

log = logging.getLogger("cost_scanner.discovery")

# Services whose compute we enrich with uptime + cost via describe calls.
_ENRICHED_SERVICES = {"ec2", "rds", "eks", "lambda"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _tags_from_list(tag_list: list[dict] | None) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in (tag_list or []) if "Key" in t}


def _arn_for_ec2(region: str, account_id: str, instance_id: str) -> str:
    return f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"


def _arn_for_rds(region: str, account_id: str, identifier: str) -> str:
    return f"arn:aws:rds:{region}:{account_id}:db:{identifier}"


def _arn_for_eks(region: str, account_id: str, name: str) -> str:
    return f"arn:aws:eks:{region}:{account_id}:cluster/{name}"


def _uptime_hours(launch: Optional[datetime], now: datetime) -> Optional[float]:
    if launch is None:
        return None
    if launch.tzinfo is None:
        launch = launch.replace(tzinfo=timezone.utc)
    return round((now - launch).total_seconds() / 3600.0, 1)


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
def discover(
    rules: OwnershipRules,
    rates: Rates,
    session: Optional[boto3.Session] = None,
    only_owned: bool = True,
) -> DiscoveredReport:
    """Inventory owned resources in the session's account/region.

    Parameters
    ----------
    rules:
        Ownership rules (which tags = "me" vs the SA team).
    rates:
        Rate resolver used to price always-on compute.
    session:
        boto3 session to use.  Defaults to the ambient ``AWS_PROFILE`` /
        ``AWS_DEFAULT_REGION`` environment.
    only_owned:
        When True (default) unclassified resources are dropped.  Set False
        to keep everything for debugging.
    """
    session = session or boto3.Session()
    region = session.region_name or "us-east-2"
    sts = session.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    ec2 = session.client("ec2")
    rds = session.client("rds")
    eks = session.client("eks")
    lam = session.client("lambda")
    tagging = session.client("resourcegroupstaggingapi")

    now = _now()
    report = DiscoveredReport(account_id=account_id, region=region, generated_at=now)

    # ---- EC2 running instances ------------------------------------------ #
    _discover_ec2(report, ec2, region, account_id, rules, rates, now, only_owned)

    # ---- RDS DB instances (standalone; Aurora handled as a note) ------- #
    _discover_rds(report, rds, region, account_id, rules, rates, now, only_owned)

    # ---- EKS clusters (control plane) ---------------------------------- #
    _discover_eks(report, eks, region, account_id, rules, rates, now, only_owned)

    # ---- Lambda functions (counted, not wall-clock charged) ------------ #
    _discover_lambda(report, lam, region, account_id, rules, now, only_owned)

    # ---- Everything else, by service count ----------------------------- #
    _discover_other(report, tagging, rules, only_owned)

    return report


# --------------------------------------------------------------------------- #
# Per-service discoverers
# --------------------------------------------------------------------------- #
def _discover_ec2(
    report: DiscoveredReport,
    ec2,
    region: str,
    account_id: str,
    rules: OwnershipRules,
    rates: Rates,
    now: datetime,
    only_owned: bool,
) -> None:
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate():
        for resv in page.get("Reservations", []):
            for inst in resv.get("Instances", []):
                state = inst.get("State", {}).get("Name", "")
                if state != "running":
                    # Stopped instances may still belong to the user; keep them
                    # so the report can flag "stopped but billable (EBS)".
                    pass
                tags = _tags_from_list(inst.get("Tags"))
                category = rules.classify(tags)
                if only_owned and category == Category.UNCLASSIFIED:
                    continue
                inst_id = inst["InstanceId"]
                launch = inst.get("LaunchTime")
                upt = _uptime_hours(launch, now)
                rate, src = rates.ec2_rate(inst.get("InstanceType", ""))
                report.ec2_instances.append(
                    Ec2Instance(
                        arn=_arn_for_ec2(region, account_id, inst_id),
                        service="ec2",
                        resource_id=inst_id,
                        name=tags.get("Name") or inst_id,
                        tags=tags,
                        category=category,
                        instance_type=inst.get("InstanceType"),
                        state=state,
                        launch_time=launch,
                        region=region,
                        uptime_hours=upt,
                        hourly_rate=rate,
                        estimated_cost=round(upt * rate, 2) if upt and rate else 0.0,
                        rate_source=src,
                    )
                )


def _discover_rds(
    report: DiscoveredReport,
    rds,
    region: str,
    account_id: str,
    rules: OwnershipRules,
    rates: Rates,
    now: datetime,
    only_owned: bool,
) -> None:
    try:
        paginator = rds.get_paginator("describe_db_instances")
        pages = paginator.paginate()
    except Exception as exc:  # pragma: no cover - RDS not enabled in some accounts
        log.warning("describe_db_instances failed: %s", exc)
        pages = []
    for page in pages:
        for db in page.get("DBInstances", []):
            # Skip Aurora (served by a cluster); the cluster owns the storage.
            if db.get("DBClusterIdentifier"):
                continue
            tags = _tags_from_list(db.get("TagList"))
            category = rules.classify(tags)
            if only_owned and category == Category.UNCLASSIFIED:
                continue
            ident = db["DBInstanceIdentifier"]
            create_time = db.get("InstanceCreateTime")
            upt = _uptime_hours(create_time, now)
            engine = db.get("Engine", "")
            multi_az = bool(db.get("MultiAZ"))
            rate, src = rates.rds_rate(db.get("DBInstanceClass", ""), engine, multi_az)
            report.rds_instances.append(
                RdsInstance(
                    arn=_arn_for_rds(region, account_id, ident),
                    service="rds",
                    resource_id=ident,
                    name=tags.get("Name") or ident,
                    tags=tags,
                    category=category,
                    db_instance_class=db.get("DBInstanceClass"),
                    engine=engine,
                    engine_version=db.get("EngineVersion"),
                    state=db.get("DBInstanceStatus", ""),
                    create_time=create_time,
                    multi_az=multi_az,
                    region=region,
                    uptime_hours=upt,
                    hourly_rate=rate,
                    estimated_cost=round(upt * rate, 2) if upt and rate else 0.0,
                    rate_source=src,
                )
                )

    # Aurora clusters: report separately (their compute instances are RDS, but
    # clusters with no instances still show as clusters).
    _discover_rds_clusters(report, rds, region, account_id, rules, now, only_owned)


def _discover_rds_clusters(
    report: DiscoveredReport, rds, region, account_id, rules, now, only_owned
) -> None:
    try:
        clusters = rds.describe_db_clusters().get("DBClusters", []) or []
    except Exception as exc:  # pragma: no cover
        log.warning("describe_db_clusters failed: %s", exc)
        clusters = []
    for cl in clusters:
        arn = cl.get("DBClusterArn", _arn_for_rds(region, account_id, cl["DBClusterIdentifier"]))
        tags = _tags_from_list(cl.get("TagList"))
        # Aurora clusters don't carry TagList in describe output -> fetch.
        if not tags:
            try:
                tags = _tags_from_list(rds.list_tags_for_resource(ResourceName=arn).get("TagList", []))
            except Exception:
                tags = {}
        category = rules.classify(tags)
        if only_owned and category == Category.UNCLASSIFIED:
            continue
        created = cl.get("ClusterCreateTime")
        upt = _uptime_hours(created, now)
        report.rds_instances.append(
            RdsInstance(
                arn=arn,
                service="rds:cluster",
                resource_id=cl["DBClusterIdentifier"],
                name=cl["DBClusterIdentifier"],
                tags=tags,
                category=category,
                db_instance_class="(aurora-cluster)",
                engine=cl.get("Engine", ""),
                engine_version=None,
                state=cl.get("Status", ""),
                create_time=created,
                multi_az=bool(cl.get("MultiAZ")),
                region=region,
                uptime_hours=upt,
                hourly_rate=0.0,
                estimated_cost=0.0,
                rate_source="cluster-not-priced",
            )
        )


def _discover_eks(
    report: DiscoveredReport,
    eks,
    region: str,
    account_id: str,
    rules: OwnershipRules,
    rates: Rates,
    now: datetime,
    only_owned: bool,
) -> None:
    try:
        names = eks.list_clusters().get("clusters", []) or []
    except Exception as exc:  # pragma: no cover - EKS not enabled
        log.warning("list_clusters failed: %s", exc)
        return
    for name in names:
        try:
            desc = eks.describe_cluster(name=name)
        except Exception as exc:
            log.warning("describe_cluster(%s) failed: %s", name, exc)
            continue
        cl = desc.get("cluster", {})
        tags = dict(cl.get("tags") or {})
        category = rules.classify(tags)
        if only_owned and category == Category.UNCLASSIFIED:
            continue
        created = cl.get("createdAt")
        upt = _uptime_hours(created, now)
        rate, src = rates.eks_rate()
        report.eks_clusters.append(
            EksCluster(
                arn=_arn_for_eks(region, account_id, name),
                service="eks",
                resource_id=name,
                name=name,
                tags=tags,
                category=category,
                created_at=created,
                version=cl.get("version"),
                region=region,
                endpoint=cl.get("endpoint"),
                uptime_hours=upt,
                hourly_rate=rate,
                estimated_cost=round(upt * rate, 2) if upt else 0.0,
                rate_source=src,
            )
        )


def _discover_lambda(
    report: DiscoveredReport,
    lam,
    region: str,
    account_id: str,
    rules: OwnershipRules,
    now: datetime,
    only_owned: bool,
) -> None:
    paginator = lam.get_paginator("list_functions")
    for page in paginator.paginate():
        for fn in page.get("Functions", []):
            arn = fn["FunctionArn"]
            tags = {}
            try:
                tags = {k: v for k, v in (lam.list_tags(Resource=arn).get("Tags") or {}).items()}
            except Exception:
                tags = {}
            category = rules.classify(tags)
            if only_owned and category == Category.UNCLASSIFIED:
                continue
            lmd = fn.get("CodeSize", 0) / (1024 * 1024)  # MB
            report.lambda_functions.append(
                LambdaFunction(
                    arn=arn,
                    service="lambda",
                    resource_id=fn["FunctionName"],
                    name=fn["FunctionName"],
                    tags=tags,
                    category=category,
                    runtime=fn.get("Runtime"),
                    timeout=fn.get("Timeout"),
                    memory_mb=fn.get("MemorySize"),
                    last_modified=fn.get("LastModified"),
                    code_size_mb=round(lmd, 2),
                )
            )


def _discover_other(
    report: DiscoveredReport, tagging, rules: OwnershipRules, only_owned: bool
) -> None:
    """Use the tagging API to count owned resources in non-compute services."""
    try:
        paginator = tagging.get_paginator("get_resources")
    except Exception as exc:  # pragma: no cover
        log.warning("tagging get_paginator failed: %s", exc)
        return
    for page in paginator.paginate(PaginationConfig={"PageSize": 100}):
        for res in page.get("ResourceTagMappingList", []):
            tags = {t["Key"]: t["Value"] for t in res.get("Tags", [])}
            category = rules.classify(tags)
            if only_owned and category == Category.UNCLASSIFIED:
                continue
            arn = res["ResourceARN"]
            service = arn.split(":")[2] if ":" in arn else "unknown"
            if service in _ENRICHED_SERVICES:
                # Already captured with richer uptime/cost detail above.
                continue
            resource_id = arn.rsplit("/", 1)[-1] if "/" in arn else arn.rsplit(":", 1)[-1]
            report.other_resources.append(
                OtherResource(
                    arn=arn,
                    service=service,
                    resource_id=resource_id,
                    name=tags.get("Name") or tags.get("hostname") or resource_id,
                    tags=tags,
                    category=category,
                )
            )
