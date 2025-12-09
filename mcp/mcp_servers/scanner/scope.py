"""
Scope validation for active scanning.
Ensures targets are explicitly allowed before any scan executes.
"""

import ipaddress
from pathlib import Path
from typing import Union

import yaml
from pydantic import BaseModel


class ScopeConfig(BaseModel):
    """Parsed scope configuration."""
    allowed_hosts: set[str]
    allowed_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]
    blocked_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]


class ScopeValidator:
    """Validates scan targets against the allowlist."""

    def __init__(self, config_path: Path | str | None = None):
        if config_path is None:
            # Default to config/targets.yaml relative to project root
            config_path = Path(__file__).parent.parent.parent / "config" / "targets.yaml"

        self.config_path = Path(config_path)
        self.config = self._load_config()

    def _load_config(self) -> ScopeConfig:
        """Load and parse the targets.yaml configuration."""
        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Scope config not found: {self.config_path}\n"
                "Create config/targets.yaml with allowed scan targets."
            )

        with open(self.config_path) as f:
            raw = yaml.safe_load(f)

        allowed_hosts: set[str] = set()
        allowed_networks: list = []
        blocked_networks: list = []

        # Parse allowed targets
        for target in raw.get("allowed_targets", []):
            for host in target.get("hosts", []):
                allowed_hosts.add(host.lower())
            for network in target.get("networks", []):
                allowed_networks.append(ipaddress.ip_network(network, strict=False))

        # Parse blocked targets
        for network in raw.get("blocked_targets", []):
            blocked_networks.append(ipaddress.ip_network(network, strict=False))

        return ScopeConfig(
            allowed_hosts=allowed_hosts,
            allowed_networks=allowed_networks,
            blocked_networks=blocked_networks
        )

    def is_allowed(self, target: str) -> bool:
        """
        Check if a target is allowed to be scanned.

        Args:
            target: IP address, hostname, or CIDR range

        Returns:
            True if target is in scope, False otherwise
        """
        target = target.lower().strip()

        # Check explicit hostname match
        if target in self.config.allowed_hosts:
            return True

        # Try to parse as IP address
        try:
            ip = ipaddress.ip_address(target)

            # Check if blocked first (blocked takes precedence)
            for blocked in self.config.blocked_networks:
                if ip in blocked:
                    return False

            # Check if in allowed networks
            for allowed in self.config.allowed_networks:
                if ip in allowed:
                    return True

        except ValueError:
            # Not a valid IP, might be a hostname
            # Only allow if explicitly listed
            pass

        # Try to parse as network range
        try:
            network = ipaddress.ip_network(target, strict=False)

            # For network ranges, every address must be in an allowed network
            for allowed in self.config.allowed_networks:
                if network.subnet_of(allowed):
                    return True

        except ValueError:
            pass

        return False

    def validate_or_raise(self, target: str) -> None:
        """
        Validate target and raise exception if not allowed.

        Args:
            target: Target to validate

        Raises:
            PermissionError: If target is not in scope
        """
        if not self.is_allowed(target):
            raise PermissionError(
                f"Target '{target}' is not in scope.\n"
                f"Add it to {self.config_path} to allow scanning."
            )


# Module-level singleton for convenience
_validator: ScopeValidator | None = None


def get_validator() -> ScopeValidator:
    """Get or create the scope validator singleton."""
    global _validator
    if _validator is None:
        _validator = ScopeValidator()
    return _validator


def is_target_allowed(target: str) -> bool:
    """Check if target is allowed (convenience function)."""
    return get_validator().is_allowed(target)


def validate_target(target: str) -> None:
    """Validate target or raise PermissionError (convenience function)."""
    get_validator().validate_or_raise(target)
