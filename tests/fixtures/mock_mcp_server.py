#!/usr/bin/env python3
"""
Mock MCP server for testing the inspector.

This server responds to MCP protocol messages via STDIO.
Run with: python mock_mcp_server.py
"""

import json
import sys


def send_response(response: dict):
    """Send a JSON-RPC response."""
    print(json.dumps(response), flush=True)


def handle_request(request: dict) -> dict:
    """Handle a JSON-RPC request."""
    method = request.get("method", "")
    request_id = request.get("id")
    params = request.get("params", {})

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {
                    "name": "mock-test-server",
                    "version": "1.0.0"
                },
                "capabilities": {
                    "tools": True,
                    "resources": True,
                    "prompts": True
                }
            }
        }

    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": [
                    {
                        "name": "execute_command",
                        "description": "Execute a shell command",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "command": {
                                    "type": "string",
                                    "description": "The command to execute"
                                }
                            },
                            "required": ["command"]
                        }
                    },
                    {
                        "name": "read_file",
                        "description": "Read a file from the filesystem",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": "File path to read"
                                }
                            },
                            "required": ["path"]
                        }
                    },
                    {
                        "name": "calculator",
                        "description": "Perform safe arithmetic calculations",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "operation": {
                                    "type": "string",
                                    "enum": ["add", "subtract", "multiply", "divide"],
                                    "description": "Operation to perform"
                                },
                                "a": {"type": "number"},
                                "b": {"type": "number"}
                            },
                            "required": ["operation", "a", "b"]
                        }
                    }
                ]
            }
        }

    elif method == "resources/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "resources": [
                    {
                        "uri": "file:///app/data/config.json",
                        "name": "Application Config",
                        "mimeType": "application/json"
                    },
                    {
                        "uri": "file:///home/user/.ssh/id_rsa",
                        "name": "SSH Key (sensitive!)",
                        "mimeType": "text/plain"
                    }
                ]
            }
        }

    elif method == "prompts/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "prompts": [
                    {
                        "name": "code-review",
                        "description": "Review code for issues"
                    }
                ]
            }
        }

    elif method == "notifications/initialized":
        # Notification - no response needed
        return None

    else:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32601,
                "message": f"Method not found: {method}"
            }
        }


def main():
    """Main server loop."""
    for line in sys.stdin:
        try:
            request = json.loads(line.strip())

            # Handle notifications (no id) silently
            if "id" not in request:
                continue

            response = handle_request(request)
            if response:
                send_response(response)

        except json.JSONDecodeError:
            pass
        except Exception as e:
            # Send error response
            send_response({
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32603,
                    "message": str(e)
                }
            })


if __name__ == "__main__":
    main()
