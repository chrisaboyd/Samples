"""On-demand hourly rate lookup.

Rates are pulled from the **AWS Price List API** (``pricing.get_products``)
which is a global API reachable from ``us-east-1``.  Products are selected
per-region by the human-readable ``location`` attribute (e.g.
``US East (Ohio)`` for ``us-east-2``) plus the instance/engine attributes.

Where the API is unreachable or a product is missing (some older/less common
types, or IAM throttling), a small **fallback table** of us-east-2 rates is
used so the report always shows a number.  Every rate is tagged with a
``source`` of:

* ``live``     -- fetched from the Price List API this run
* ``fallback`` -- taken from the hardcoded table
* ``fixed``    -- a known constant (e.g. the EKS control-plane charge)
* ``unknown``  -- no rate could be determined (rate is 0; the resource is
  still listed so it can be investigated)
"""

from __future__ import annotations

import os
import logging
from functools import lru_cache
from typing import Optional

import boto3

log = logging.getLogger("cost_scanner.rates")

# --------------------------------------------------------------------------- #
# Region -> Price List "location" name
# --------------------------------------------------------------------------- #
_REGION_TO_LOCATION = {
    "us-east-1": "US East (N. Virginia)",
    "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)",
    "us-west-2": "US West (Oregon)",
    "eu-west-1": "EU (Ireland)",
    "eu-central-1": "EU (Frankfurt)",
    "ap-southeast-1": "Asia Pacific (Singapore)",
    "ap-southeast-2": "Asia Pacific (Sydney)",
    "ap-northeast-1": "Asia Pacific (Tokyo)",
}

# Map the RDS ``Engine`` value returned by describe-db-instances
# (lowercase short name) -> the ``databaseEngine`` value used by the
# Price List API (capitalised / spaced).
_RDS_ENGINE_MAP = {
    "postgres": "PostgreSQL",
    "mysql": "MySQL",
    "mariadb": "MariaDB",
    "oracle-ee": "Oracle",
    "oracle-se2": "Oracle",
    "oracle-se1": "Oracle",
    "oracle-se": "Oracle",
    "sqlserver": "SQL Server",
    "sqlserver-ee": "SQL Server",
    "sqlserver-se": "SQL Server",
    "sqlserver-web": "SQL Server",
    "sqlserver-express": "SQL Server",
    "aurora": "Aurora",
    "aurora-postgresql": "Aurora-PostgreSQL",
    "aurora-mysql": "Aurora-MySQL",
    "neptune": "Neptune",
    "docdb": "DocumentDB",
}


# --------------------------------------------------------------------------- #
# Fallback on-demand rates (us-east-2 / Ohio).  Used only if the Price List
# API cannot resolve a rate.  Values are from the AWS pricing page at the time
# of writing; each is flagged "fallback" in the report.
# --------------------------------------------------------------------------- #
_EC2_FALLBACK_US_EAST_2 = {
    "t4g.nano": 0.0042,
    "t4g.micro": 0.0084,
    "t4g.small": 0.0168,
    "t4g.medium": 0.0336,
    "t3.nano": 0.0052,
    "t3.micro": 0.0104,
    "t3.small": 0.0208,
    "t3.medium": 0.1092,
    "t3.large": 0.2208,
    "t3.xlarge": 0.4320,
    "t3.2xlarge": 0.8640,
    "m5.large": 0.3840,
    "m5.xlarge": 0.6720,
    "m5.2xlarge": 1.1520,
    "m6i.large": 0.5040,
    "m6i.xlarge": 0.7560,
    "m7g.large": 0.1472,
    "m7g.xlarge": 0.2944,
    "r6i.large": 0.6480,
    "r6i.xlarge": 1.0440,
    "c6i.large": 0.4352,
    "c6i.xlarge": 0.8704,
    "c7g.large": 0.1408,
    "r7g.large": 0.5040,
    "x2ie.metal": 0.00,  # placeholder, never a "small" waste
}

_RDS_FALLBACK_US_EAST_2 = {
    # class: (single-az hourly, multi-az hourly) -- postgres engine family
    "db.t4g.micro": (0.018, 0.036),
    "db.t4g.small": (0.036, 0.072),
    "db.t4g.medium": (0.0645, 0.129),
    "db.t4g.large": (0.129, 0.258),
    "db.m7g.large": (0.168, 0.336),
    "db.m7g.xlarge": (0.337, 0.674),
    "db.m7g.2xlarge": (0.674, 1.348),
    "db.m6i.large": (0.226, 0.452),
    "db.m6i.xlarge": (0.452, 0.904),
    "db.m5.large": (0.226, 0.452),
    "db.m5.xlarge": (0.452, 0.904),
    "db.r7g.large": (0.272, 0.544),
    "db.r7g.xlarge": (0.544, 1.088),
}

# EKS control plane = per-AZ-hour.  us-east-2 Ohio = $0.10/cluster-hour.
EKS_CONTROL_PLANE_RATE = 0.10


class Rates:
    """Resolve on-demand hourly rates for EC2 / RDS / EKS."""

    def __init__(
        self,
        region: str = "us-east-2",
        pricing_client: Optional[object] = None,
        max_scan_pages: int = 5,
    ) -> None:
        self.region = region
        self.location = _REGION_TO_LOCATION.get(region, "")
        # Price List API is global; standard endpoint is us-east-1.
        self._pricing = pricing_client or boto3.client("pricing", region_name="us-east-1")
        self.max_scan_pages = max_scan_pages
        self._cache: dict[tuple[str, str], tuple[float, str]] = {}

    # ------------------------------------------------------------------ #
    # public API
    # ------------------------------------------------------------------ #
    def ec2_rate(self, instance_type: str) -> tuple[float, str]:
        """Return ``(hourly_rate_usd, source)`` for an EC2 instance type."""
        if not instance_type:
            return 0.0, "unknown"
        key = ("ec2", instance_type)
        if key in self._cache:
            return self._cache[key]

        rate, src = self._price_list_ec2(instance_type)
        if rate is None:
            rate, src = self._fallback_ec2(instance_type)
        rate = round(rate, 6)
        self._cache[key] = (rate, src)
        return rate, src

    def rds_rate(
        self, instance_class: str, engine: str, multi_az: bool = False
    ) -> tuple[float, str]:
        """Return ``(hourly_rate_usd, source)`` for an RDS instance."""
        if not instance_class:
            return 0.0, "unknown"
        # Use Single-AZ rate as the base; Multi-AZ is ~2x on-demand.
        key = ("rds", instance_class, engine or "", bool(multi_az))
        if key in self._cache:
            return self._cache[key]

        rate, src = self._price_list_rds(instance_class, engine)
        if rate is None:
            rate, src = self._fallback_rds(instance_class, multi_az)
        if multi_az and src != "unknown":
            rate = rate * 2.0
        rate = round(rate, 6)
        self._cache[key] = (rate, src)
        return rate, src

    def eks_rate(self) -> tuple[float, str]:
        """EKS control-plane hourly rate (constant)."""
        return EKS_CONTROL_PLANE_RATE, "fixed"

    # ------------------------------------------------------------------ #
    # Price List API lookups
    # ------------------------------------------------------------------ #
    def _filters_for(self, **attrs: str) -> list[dict]:
        return [{"Type": "TERM_MATCH", "Field": k, "Value": v} for k, v in attrs.items()]

    def _price_list_ec2(self, instance_type: str) -> tuple[Optional[float], str]:
        filters = self._filters_for(
            instanceType=instance_type,
            operatingSystem="Linux",
            tenancy="Shared",
            capacityStatus="Used",
        )
        if self.location:
            filters.append({"Type": "TERM_MATCH", "Field": "location", "Value": self.location})
        try:
            rate = self._first_on_demand_hourly("AmazonEC2", filters)
        except Exception as exc:  # pragma: no cover - network/throttle
            log.warning("Price List API (EC2 %s) error: %s", instance_type, exc)
            rate = None
        if rate is None and self.region:
            # last resort: scan products for the type and match regionCode
            rate = self._scan_for_region("AmazonEC2", instance_type, "instanceType")
        return rate, "live" if rate is not None else (None, "unknown")

    def _price_list_rds(self, instance_class: str, engine: str) -> tuple[Optional[float], str]:
        db_engine = _RDS_ENGINE_MAP.get((engine or "").lower(), engine)
        filters = self._filters_for(
            instanceType=instance_class,
            databaseEngine=db_engine,
        )
        if self.location:
            filters.append({"Type": "TERM_MATCH", "Field": "location", "Value": self.location})
        # Single-AZ base rate; Multi-AZ handled by caller.
        filters.append({"Type": "TERM_MATCH", "Field": "deploymentOption", "Value": "Single-AZ"})
        try:
            rate = self._first_on_demand_hourly("AmazonRDS", filters)
        except Exception as exc:  # pragma: no cover
            log.warning("Price List API (RDS %s/%s) error: %s", instance_class, engine, exc)
            rate = None
        if rate is None and self.region:
            rate = self._scan_for_region("AmazonRDS", instance_class, "instanceType")
        return rate, "live" if rate is not None else (None, "unknown")

    def _min_ondemand_hourly(self, product: dict) -> Optional[float]:
        """Smallest positive ``Hrs`` on-demand price across a product's dimensions."""
        candidates: list[float] = []
        for offer in product.get("terms", {}).get("OnDemand", {}).values():
            for dim in offer.get("priceDimensions", {}).values():
                if dim.get("unit") == "Hrs":
                    try:
                        amt = float(dim["pricePerUnit"]["USD"])
                    except (KeyError, ValueError, TypeError):
                        continue
                    if amt > 0:
                        candidates.append(amt)
        return min(candidates) if candidates else None

    def _first_on_demand_hourly(self, service: str, filters: list[dict]) -> Optional[float]:
        """Return the standard on-demand **hourly** rate for a product set.

        A loose filter can match several price-list products for the same
        usage type (e.g. alternative offer dimensions).  The real
        on-demand *per-hour* rate is the smallest positive ``Hrs`` price
        across every On-Demand price dimension returned -- the larger
        values are committed-use / per-feature variants that we do not want
        to charge against "running right now" cost.
        """
        resp = self._pricing.get_products(ServiceCode=service, Filters=filters, MaxResults=10)
        best: Optional[float] = None
        for raw in resp.get("PriceList", []):
            rate = self._min_ondemand_hourly(self._parse_offer(raw))
            if rate is not None and (best is None or rate < best):
                best = rate
        return best

    def _scan_for_region(self, service, value, field) -> Optional[float]:
        """Scan up to ``max_scan_pages`` products to find a regional match."""
        paginator = self._pricing.get_paginator("get_products")
        pages = paginator.paginate(
            ServiceCode=service,
            Filters=[{"Type": "TERM_MATCH", "Field": field, "Value": value}],
            PaginationConfig={"PageSize": 100},
        )
        for i, page in enumerate(pages):
            if i >= self.max_scan_pages:
                break
            for raw in page.get("PriceList", []):
                product = self._parse_offer(raw)
                attrs = product.get("product", {}).get("attributes", {})
                if attrs.get("regionCode") == self.region:
                    rate = self._min_ondemand_hourly(product)
                    if rate is not None:
                        return rate
        return None

    @staticmethod
    def _parse_offer(raw: dict | str) -> dict:
        import json

        if isinstance(raw, str):
            return json.loads(raw)
        # Older SDK shapes wrapped the offer under a SKU key.
        return raw

    # ------------------------------------------------------------------ #
    # Fallback tables
    # ------------------------------------------------------------------ #
    def _fallback_ec2(self, instance_type: str) -> tuple[float, str]:
        rate = _EC2_FALLBACK_US_EAST_2.get(instance_type)
        if rate is not None:
            return rate, "fallback"
        log.info("No fallback rate for EC2 %s", instance_type)
        return 0.0, "unknown"

    def _fallback_rds(self, instance_class: str, multi_az: bool) -> tuple[float, str]:
        entry = _RDS_FALLBACK_US_EAST_2.get(instance_class)
        if entry:
            single, _ = entry
            return single, "fallback"
        log.info("No fallback rate for RDS %s", instance_class)
        return 0.0, "unknown"
