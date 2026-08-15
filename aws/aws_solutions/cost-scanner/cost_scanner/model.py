"""Data model for discovered AWS resources, cost estimates and the final report.

Everything here is a plain dataclass so it serialises trivially to dict / JSON
for both the Lambda -> Slack path and the local -> Obsidian Markdown path.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class Category(str, Enum):
    """Who (according to ownership tags) a resource belongs to."""

    MINE = "mine"
    SOLUTIONS_ARCHITECT = "solutions-architect"
    BOTH = "both"
    UNCLASSIFIED = "unclassified"


# --------------------------------------------------------------------------- #
# Base resource
# --------------------------------------------------------------------------- #
@dataclass
class Resource:
    """Common fields shared by every discovered resource."""

    arn: str = ""
    service: str = ""
    resource_id: str = ""
    name: Optional[str] = None
    tags: dict[str, str] = field(default_factory=dict)
    category: Category = Category.UNCLASSIFIED

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        return d


# --------------------------------------------------------------------------- #
# Always-on compute resources (the ones that "waste" money by running)
# --------------------------------------------------------------------------- #
@dataclass
class Ec2Instance(Resource):
    service: str = "ec2"
    instance_type: Optional[str] = None
    state: Optional[str] = None
    launch_time: Optional[datetime] = None
    region: Optional[str] = None

    # Cost fields, populated by cost.compute_costs()
    uptime_hours: Optional[float] = None
    hourly_rate: Optional[float] = None
    estimated_cost: Optional[float] = None  # uptime_hours * hourly_rate
    rate_source: Optional[str] = None  # 'live' | 'fallback' | 'unknown'


@dataclass
class RdsInstance(Resource):
    service: str = "rds"
    db_instance_class: Optional[str] = None
    engine: Optional[str] = None
    engine_version: Optional[str] = None
    state: Optional[str] = None
    create_time: Optional[datetime] = None
    multi_az: bool = False
    region: Optional[str] = None

    uptime_hours: Optional[float] = None
    hourly_rate: Optional[float] = None
    estimated_cost: Optional[float] = None
    rate_source: Optional[str] = None


@dataclass
class EksCluster(Resource):
    """EKS control-plane cost (the node pool cost is captured via EC2)."""

    service: str = "eks"
    created_at: Optional[datetime] = None
    version: Optional[str] = None
    region: Optional[str] = None
    endpoint: Optional[str] = None

    uptime_hours: Optional[float] = None
    hourly_rate: Optional[float] = None  # EKS control plane on-demand rate
    estimated_cost: Optional[float] = None
    rate_source: Optional[str] = None


# --------------------------------------------------------------------------- #
# Resources that are NOT charged for wall-clock uptime
# --------------------------------------------------------------------------- #
@dataclass
class LambdaFunction(Resource):
    service: str = "lambda"
    runtime: Optional[str] = None
    timeout: Optional[int] = None
    memory_mb: Optional[int] = None
    last_modified: Optional[datetime] = None
    provisioned_concurrent_executions: Optional[int] = None
    code_size_mb: Optional[float] = None


@dataclass
class OtherResource(Resource):
    """A tagged resource we count but don't charge wall-clock for."""

    service: str = "other"


# --------------------------------------------------------------------------- #
# Aggregations
# --------------------------------------------------------------------------- #
@dataclass
class DiscoveredReport:
    """Raw inventory produced by :func:`discovery.discover`."""

    account_id: str
    region: str
    generated_at: datetime = field(default_factory=datetime.utcnow)

    ec2_instances: list[Ec2Instance] = field(default_factory=list)
    rds_instances: list[RdsInstance] = field(default_factory=list)
    eks_clusters: list[EksCluster] = field(default_factory=list)
    lambda_functions: list[LambdaFunction] = field(default_factory=list)
    other_resources: list[OtherResource] = field(default_factory=list)

    def all_compute(self) -> list[Ec2Instance | RdsInstance | EksCluster]:
        return [*self.ec2_instances, *self.rds_instances, *self.eks_clusters]


@dataclass
class Report:
    """Final, cost-enriched report handed to the renderers."""

    discovered: DiscoveredReport
    # Cross-check from Cost Explorer (best-effort; may be empty)
    ce_mtd_cost: Optional[float] = None
    ce_mtd_currency: str = "USD"

    # ----- derived totals -----
    mine_count: int = 0
    sa_team_count: int = 0
    both_count: int = 0

    mine_estimated_cost: float = 0.0
    sa_team_estimated_cost: float = 0.0
    total_estimated_cost: float = 0.0
    total_burn_rate: float = 0.0  # $/hour, right now, if nothing is stopped

    # per-service cost rollup
    ec2_estimated_cost: float = 0.0
    rds_estimated_cost: float = 0.0
    eks_estimated_cost: float = 0.0

    notes: list[str] = field(default_factory=list)
