# Agents

Agents are LLM-powered orchestrators that use MCP tools to accomplish tasks.

## What is an Agent?

An agent:
1. Receives a task from the user
2. Connects to one or more MCP servers
3. Uses an LLM to decide which tools to call
4. Executes tool calls and feeds results back to the LLM
5. Continues until the task is complete

## Creating an Agent

### 1. Create the agent file

```
agents/
├── __init__.py
├── base.py           # Shared infrastructure (don't modify)
├── your_agent.py     # Your agent implementation
└── providers/
```

### 2. Implement your agent

```python
"""
Your Agent - Brief description of what this agent does.
"""

from .base import BaseAgent


class YourAgent(BaseAgent):
    """Agent for [your use case]."""

    @property
    def name(self) -> str:
        return "Your Agent"

    @property
    def mcp_server_module(self) -> str:
        # Python module path to your MCP server
        return "mcp_servers.your_server.server"

    @property
    def prompt_file(self) -> str:
        # Filename in prompts/ directory
        return "your_agent.md"

    def _default_prompt(self) -> str:
        # Fallback if prompt file doesn't exist
        return """You are a helpful assistant with access to tools.
Use the available tools to complete the user's task.
Always explain your reasoning and provide structured output."""
```

### 3. Register in __init__.py

```python
from .your_agent import YourAgent

__all__ = [
    "BaseAgent",
    "YourAgent",  # Add your agent
    # ...
]
```

### 4. Create the system prompt

See [prompts/README.md](../prompts/README.md) for guidance on writing effective prompts.

## Using Your Agent

### From code

```python
import asyncio
from agents import YourAgent, get_provider

async def main():
    # Use default provider (Poolside)
    agent = YourAgent()

    # Or specify a provider
    provider = get_provider("poolside", model="malibu_agent_1201_2k")
    agent = YourAgent(provider=provider)

    # Run a task
    result = await agent.run(
        task="Your task description here",
        verbose=True  # Show tool calls
    )
    print(result)

asyncio.run(main())
```

### From CLI

See [cli.py](../cli.py) for wiring agents to CLI commands.

## The Agentic Loop

The base agent implements this loop:

```
┌─────────────────────────────────────────────────────┐
│                 User provides task                  │
└─────────────────────┬───────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────┐
│           Send to LLM with available tools          │
└─────────────────────┬───────────────────────────────┘
                      ▼
            ┌─────────────────────┐
            │  LLM Response       │
            │                     │
            │  stop_reason?       │
            └─────────┬───────────┘
                      │
         ┌────────────┼────────────┐
         ▼            ▼            ▼
    "end_turn"    "tool_use"    other
         │            │            │
         ▼            ▼            ▼
    Return        Execute       Return
    content       tools         content
                     │
                     ▼
              ┌──────────────┐
              │ Add tool     │
              │ results to   │
              │ messages     │
              └──────┬───────┘
                     │
                     └──────► (back to "Send to LLM")
```

## Multi-Server Agents

For agents that need multiple MCP servers, override the `run` method:

```python
class MultiServerAgent(BaseAgent):
    async def run(self, task: str, verbose: bool = False) -> str:
        # Connect to multiple servers
        servers = [
            StdioServerParameters(command="python", args=["-m", "mcp_servers.server1.server"]),
            StdioServerParameters(command="python", args=["-m", "mcp_servers.server2.server"]),
        ]

        all_tools = []
        sessions = []

        for server_params in servers:
            # ... connect and gather tools from each server
            pass

        # Run agentic loop with combined tools
        # Route tool calls to appropriate server based on tool name
```

## Error Handling

The base agent handles common errors:

- **Tool execution errors**: Returned to LLM as error messages
- **MCP connection failures**: Raised to caller
- **LLM API errors**: Raised to caller

For custom error handling, override methods as needed.

## Customization Points

| Method | Purpose | Override when... |
|--------|---------|------------------|
| `run()` | Main entry point | Multi-server, custom loops |
| `_load_system_prompt()` | Load prompt file | Dynamic prompts |
| `_default_prompt()` | Fallback prompt | Required |
| `name` | Display name | Required |
| `mcp_server_module` | MCP server path | Required |
| `prompt_file` | Prompt filename | Required |
