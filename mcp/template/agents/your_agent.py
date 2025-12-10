"""
Your Agent - [DESCRIBE WHAT YOUR AGENT DOES]

This is a template agent. Replace this description and customize
the properties below for your use case.
"""

from .base import BaseAgent


class YourAgent(BaseAgent):
    """
    Agent for [your use case].

    This agent connects to the YourServer MCP server and uses its tools
    to accomplish tasks related to [your domain].
    """

    @property
    def name(self) -> str:
        """Agent name for display."""
        return "Your Agent"

    @property
    def mcp_server_module(self) -> str:
        """
        Python module path for the MCP server.

        This should match how you'd run the server:
        python -m mcp_servers.your_server.server
        """
        return "mcp_servers.your_server.server"

    @property
    def prompt_file(self) -> str:
        """
        Filename of the system prompt in prompts/ directory.

        The prompt file should contain instructions for the LLM
        on how to use the available tools effectively.
        """
        return "your_agent.md"

    def _default_prompt(self) -> str:
        """
        Default system prompt if the prompt file doesn't exist.

        This is a fallback - prefer using a dedicated prompt file
        for easier iteration and version control.
        """
        return """You are a helpful assistant with access to specialized tools.

Your goal is to help the user accomplish their task by:
1. Understanding what they need
2. Using the available tools appropriately
3. Providing clear, structured output

When using tools:
- Explain what you're doing and why
- Handle errors gracefully
- Summarize results in a useful format

Always be clear about what you found and any limitations or caveats."""
