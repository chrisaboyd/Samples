"""
Scanner MCP Server - Active Scanning Tools

Exposes nmap, feroxbuster, and nikto as MCP tools.
All tools validate targets against the scope allowlist before execution.
"""

import asyncio
import json
import logging

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from .tools.nmap import run_nmap_scan, SCAN_PROFILES
from .tools.feroxbuster import run_feroxbuster
from .tools.nikto import run_nikto

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scanner-mcp")

# Create MCP server
server = Server("scanner-server")


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available scanning tools."""
    return [
        Tool(
            name="nmap_scan",
            description=(
                "Run an nmap port scan against a target. "
                "Supports multiple scan profiles: quick (fast common ports), "
                "full (all ports with version detection), stealth (slow SYN scan), "
                "service_version (version detection), vuln_scripts (vulnerability scripts), "
                "aggressive (OS detection + scripts). "
                "Target must be in the allowed scope."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname to scan"
                    },
                    "profile": {
                        "type": "string",
                        "enum": list(SCAN_PROFILES.keys()),
                        "default": "quick",
                        "description": "Scan profile determining speed/depth tradeoff"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port specification (e.g., '22,80,443' or '1-1000'). Optional."
                    },
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="feroxbuster",
            description=(
                "Run feroxbuster directory brute-forcing against a web server. "
                "Discovers hidden files and directories. "
                "Target URL must be in the allowed scope."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL (e.g., http://192.168.1.100)"
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Path to wordlist file. Uses common.txt if not specified."
                    },
                    "extensions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "File extensions to check (e.g., ['php', 'html', 'txt'])"
                    },
                    "threads": {
                        "type": "integer",
                        "default": 50,
                        "description": "Number of concurrent threads"
                    },
                    "depth": {
                        "type": "integer",
                        "default": 2,
                        "description": "Recursion depth"
                    },
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="nikto",
            description=(
                "Run nikto web server vulnerability scanner. "
                "Checks for dangerous files, outdated software, and misconfigurations. "
                "Target must be in the allowed scope."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host (IP or hostname)"
                    },
                    "port": {
                        "type": "integer",
                        "default": 80,
                        "description": "Target port"
                    },
                    "ssl": {
                        "type": "boolean",
                        "default": False,
                        "description": "Use SSL/HTTPS"
                    },
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="list_profiles",
            description="List available nmap scan profiles and their descriptions.",
            inputSchema={
                "type": "object",
                "properties": {},
            }
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Execute a scanning tool."""
    logger.info(f"Tool called: {name} with args: {arguments}")

    try:
        if name == "nmap_scan":
            result = await run_nmap_scan(
                target=arguments["target"],
                profile=arguments.get("profile", "quick"),
                ports=arguments.get("ports"),
            )
            # Return structured JSON result
            return [TextContent(
                type="text",
                text=json.dumps(result.model_dump(), indent=2)
            )]

        elif name == "feroxbuster":
            result = await run_feroxbuster(
                url=arguments["url"],
                wordlist=arguments.get("wordlist"),
                extensions=arguments.get("extensions"),
                threads=arguments.get("threads", 50),
                depth=arguments.get("depth", 2),
            )
            return [TextContent(
                type="text",
                text=json.dumps(result.model_dump(), indent=2)
            )]

        elif name == "nikto":
            result = await run_nikto(
                target=arguments["target"],
                port=arguments.get("port", 80),
                ssl=arguments.get("ssl", False),
            )
            return [TextContent(
                type="text",
                text=json.dumps(result.model_dump(), indent=2)
            )]

        elif name == "list_profiles":
            profiles_info = {
                name: config["description"]
                for name, config in SCAN_PROFILES.items()
            }
            return [TextContent(
                type="text",
                text=json.dumps(profiles_info, indent=2)
            )]

        else:
            raise ValueError(f"Unknown tool: {name}")

    except PermissionError as e:
        # Scope validation failed
        logger.warning(f"Scope violation: {e}")
        return [TextContent(
            type="text",
            text=json.dumps({"error": "scope_violation", "message": str(e)})
        )]
    except FileNotFoundError as e:
        # Tool not installed
        logger.error(f"Tool not found: {e}")
        return [TextContent(
            type="text",
            text=json.dumps({"error": "tool_not_found", "message": str(e)})
        )]
    except Exception as e:
        logger.exception(f"Error executing {name}")
        return [TextContent(
            type="text",
            text=json.dumps({"error": "execution_error", "message": str(e)})
        )]


async def main():
    """Run the MCP server."""
    logger.info("Starting Scanner MCP Server...")
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
