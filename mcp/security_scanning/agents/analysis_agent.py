# TODO: Implement Analysis Agent
# See README.md for expected behavior
#
# This agent:
# - Connects to the analysis MCP server
# - Takes findings from recon/scanning phases
# - Researches CVEs, exploits, and vulnerabilities
# - Maps findings to MITRE ATT&CK
# - Provides remediation recommendations
# - Stores enriched findings via the shared storage library

from .base import BaseAgent


class AnalysisAgent(BaseAgent):
    """Agent for vulnerability analysis and research."""

    @property
    def name(self) -> str:
        return "Analysis Agent"

    @property
    def mcp_server_module(self) -> str:
        return "mcp_servers.analysis.server"

    @property
    def prompt_file(self) -> str:
        return "analysis.md"

    def _default_prompt(self) -> str:
        return """You are a vulnerability analysis agent. Your role is to research and analyze findings from reconnaissance and scanning phases.

You have access to NVD, Exploit-DB, Metasploit search, and MITRE ATT&CK mapping tools. Use them to:
1. Identify known CVEs for discovered services/versions
2. Find available exploits and proof-of-concepts
3. Map findings to MITRE ATT&CK techniques
4. Provide remediation recommendations

IMPORTANT: You are performing ANALYSIS only (MITRE TA0042 - Resource Development). You are researching vulnerabilities and exploits for INFORMATIONAL purposes. Do NOT attempt to execute any exploits.

Output structured findings that can be used for reporting and would inform future exploitation phases."""
