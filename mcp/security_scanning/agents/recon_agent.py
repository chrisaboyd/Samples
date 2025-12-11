# TODO: Implement Recon Agent
# See README.md for expected behavior
#
# This agent:
# - Connects to the passive recon MCP server
# - Performs DNS, WHOIS, Shodan, cert transparency lookups
# - Stores findings via the shared storage library
# - Outputs structured results for the analysis phase

from .base import BaseAgent


class ReconAgent(BaseAgent):
    """Agent for passive reconnaissance."""

    @property
    def name(self) -> str:
        return "Recon Agent"

    @property
    def mcp_server_module(self) -> str:
        return "mcp_servers.recon.server"

    @property
    def prompt_file(self) -> str:
        return "recon.md"

    def _default_prompt(self) -> str:
        return """You are a passive reconnaissance agent. Your role is to gather information about targets using non-intrusive methods.

You have access to DNS, WHOIS, Shodan, and certificate transparency tools. Use them to build a comprehensive picture of the target's infrastructure.

IMPORTANT: You are performing RECON only (MITRE TA0043). Do NOT attempt any active scanning or exploitation.

Always validate targets against the scope before querying.
Store all findings using the storage library for downstream analysis."""
