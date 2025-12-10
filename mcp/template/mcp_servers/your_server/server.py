"""
Your MCP Server - [DESCRIBE YOUR SERVER PURPOSE HERE]

This is a template MCP server. Replace this description and implement
your own tools in the tools/ directory.
"""

import asyncio
import json
import logging

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Import your tool implementations
# from .tools.your_tool import run_your_tool

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("your-mcp-server")

# Create MCP server
server = Server("your-server-name")


@server.list_tools()
async def list_tools() -> list[Tool]:
    """
    List available tools.

    Each tool needs:
    - name: Unique identifier (snake_case)
    - description: What the tool does (helps LLM decide when to use it)
    - inputSchema: JSON Schema for parameters
    """
    return [
        # TODO: Define your tools here
        # Example:
        Tool(
            name="example_tool",
            description=(
                "An example tool that does something. "
                "Replace this with your actual tool."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "input_param": {
                        "type": "string",
                        "description": "Description of what this parameter does"
                    },
                    "optional_param": {
                        "type": "integer",
                        "default": 10,
                        "description": "An optional parameter with a default"
                    },
                },
                "required": ["input_param"]
            }
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """
    Execute a tool.

    This is called when an agent invokes a tool. Route to the
    appropriate implementation based on the tool name.
    """
    logger.info(f"Tool called: {name} with args: {arguments}")

    try:
        if name == "example_tool":
            # TODO: Replace with your actual tool implementation
            result = {
                "status": "success",
                "message": f"Processed: {arguments.get('input_param')}",
                "optional_value": arguments.get("optional_param", 10)
            }
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        # Add more tools here:
        # elif name == "another_tool":
        #     result = await run_another_tool(...)
        #     return [TextContent(type="text", text=json.dumps(result))]

        else:
            raise ValueError(f"Unknown tool: {name}")

    except ValueError as e:
        # Input validation errors
        logger.warning(f"Validation error: {e}")
        return [TextContent(
            type="text",
            text=json.dumps({"error": "validation_error", "message": str(e)})
        )]
    except Exception as e:
        # Unexpected errors
        logger.exception(f"Error executing {name}")
        return [TextContent(
            type="text",
            text=json.dumps({"error": "execution_error", "message": str(e)})
        )]


async def main():
    """Run the MCP server."""
    logger.info("Starting MCP Server...")
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
