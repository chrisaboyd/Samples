"""
cost_scanner
============

A reusable engine that inventories AWS resources owned by a specific
principal (and a named team) in an account, estimates how much
*accumulated run cost* each of those resources has incurred, and renders
the result as Markdown.

It is designed to run in two places:

* **locally** (``scan.py``)  -- with the operator's SSO profile, writing a
  dated Markdown report into an Obsidian vault folder, and optionally
  cross-posting a short summary to Slack.
* **in AWS** (``app.py`` Lambda) -- with an execution role, posting the
  summary to Slack on a daily schedule via EventBridge.  A Lambda *cannot*
  write to a local filesystem, so the Obsidian path is local-only.

Only the Python standard library + boto3 (present in every Lambda runtime
and in the local CLI's AWS tooling) are required.
"""

from .model import (
    Category,
    Resource,
    Ec2Instance,
    RdsInstance,
    EksCluster,
    LambdaFunction,
    OtherResource,
    DiscoveredReport,
    Report,
)

__all__ = [
    "Category",
    "Resource",
    "Ec2Instance",
    "RdsInstance",
    "EksCluster",
    "LambdaFunction",
    "OtherResource",
    "DiscoveredReport",
    "Report",
]

__version__ = "0.1.0"
