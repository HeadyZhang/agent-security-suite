"""MCP protocol client with STDIO and SSE transports."""

import asyncio
import json
import logging
import sys
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod
from enum import Enum

logger = logging.getLogger(__name__)

# Windows subprocess creation flags
_IS_WINDOWS = sys.platform == "win32"
_CREATE_NO_WINDOW = 0x08000000 if _IS_WINDOWS else 0


class TransportType(Enum):
    """MCP transport types."""
    STDIO = "stdio"
    SSE = "sse"
    STREAMABLE_HTTP = "streamable_http"


class BaseMCPTransport(ABC):
    """Base class for MCP transport implementations."""

    @abstractmethod
    async def connect(self):
        """Establish connection to MCP server."""
        pass

    @abstractmethod
    async def send(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Send a JSON-RPC request and wait for response."""
        pass

    @abstractmethod
    async def notify(self, method: str, params: Dict[str, Any]):
        """Send a JSON-RPC notification (no response expected)."""
        pass

    @abstractmethod
    async def close(self):
        """Close the connection."""
        pass


class StdioTransport(BaseMCPTransport):
    """
    STDIO transport for local MCP servers.

    Communicates with MCP server via stdin/stdout using JSON-RPC.
    """

    def __init__(self, command: str, args: Optional[list] = None, env: Optional[dict] = None):
        """
        Initialize STDIO transport.

        Args:
            command: Command to execute (e.g., "python", "node")
            args: Command arguments (e.g., ["server.py"])
            env: Environment variables
        """
        self.command = command
        self.args = args or []
        self.env = env
        self.process: Optional[asyncio.subprocess.Process] = None
        self._request_id = 0
        self._pending_requests: Dict[int, asyncio.Future] = {}
        self._reader_task: Optional[asyncio.Task] = None

    async def connect(self):
        """Start the MCP server process."""
        import os
        import subprocess

        # Prepare environment
        process_env = os.environ.copy()
        if self.env:
            process_env.update(self.env)

        # Build kwargs for subprocess creation
        kwargs: Dict[str, Any] = {
            "stdin": asyncio.subprocess.PIPE,
            "stdout": asyncio.subprocess.PIPE,
            "stderr": asyncio.subprocess.PIPE,
            "env": process_env,
        }

        # On Windows, prevent console window from appearing
        if _IS_WINDOWS:
            kwargs["creationflags"] = _CREATE_NO_WINDOW

        self.process = await asyncio.create_subprocess_exec(
            self.command, *self.args,
            **kwargs
        )

        # Start background reader
        self._reader_task = asyncio.create_task(self._read_responses())

    async def _read_responses(self):
        """Background task to read responses from server."""
        try:
            while self.process and self.process.stdout:
                line = await self.process.stdout.readline()
                if not line:
                    break

                try:
                    response = json.loads(line.decode())
                    request_id = response.get('id')

                    if request_id is not None and request_id in self._pending_requests:
                        future = self._pending_requests.pop(request_id)
                        if not future.done():
                            future.set_result(response)

                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON from server: {line}")

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Error reading from server: {e}")

    async def send(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Send a JSON-RPC request and wait for response."""
        if not self.process or not self.process.stdin:
            raise RuntimeError("Not connected")

        self._request_id += 1
        request_id = self._request_id

        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params
        }

        # Create future for response
        future: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending_requests[request_id] = future

        # Send request
        request_bytes = json.dumps(request).encode() + b"\n"
        self.process.stdin.write(request_bytes)
        await self.process.stdin.drain()

        # Wait for response with timeout
        try:
            response = await asyncio.wait_for(future, timeout=30)
        except asyncio.TimeoutError:
            self._pending_requests.pop(request_id, None)
            raise TimeoutError(f"Request {method} timed out")

        if "error" in response:
            error = response["error"]
            raise RuntimeError(f"MCP Error: {error.get('message', error)}")

        return response.get("result", {})

    async def notify(self, method: str, params: Dict[str, Any]):
        """Send a JSON-RPC notification."""
        if not self.process or not self.process.stdin:
            raise RuntimeError("Not connected")

        notification = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        }

        notification_bytes = json.dumps(notification).encode() + b"\n"
        self.process.stdin.write(notification_bytes)
        await self.process.stdin.drain()

    async def close(self):
        """Terminate the server process."""
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass

        if self.process:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()


class SSETransport(BaseMCPTransport):
    """
    SSE (Server-Sent Events) transport for remote MCP servers.

    Uses HTTP POST for requests and SSE for responses.
    """

    def __init__(self, url: str):
        """
        Initialize SSE transport.

        Args:
            url: SSE endpoint URL
        """
        self.url = url
        self.session = None
        self._request_id = 0
        self._endpoint: Optional[str] = None

    async def connect(self):
        """Connect to the SSE endpoint and get the messages URL."""
        import aiohttp

        self.session = aiohttp.ClientSession()

        # Connect to SSE endpoint to get messages URL
        try:
            async with self.session.get(self.url) as response:
                if response.status != 200:
                    raise RuntimeError(f"SSE connection failed: {response.status}")

                # Read SSE events to find endpoint
                async for line in response.content:
                    decoded = line.decode().strip()

                    if decoded.startswith("event: endpoint"):
                        next_line = await response.content.readline()
                        data = next_line.decode().strip()
                        if data.startswith("data: "):
                            self._endpoint = data[6:]
                            break

        except Exception as e:
            await self.close()
            raise RuntimeError(f"Failed to connect to SSE: {e}")

        if not self._endpoint:
            raise RuntimeError("Failed to get messages endpoint from SSE")

    async def send(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Send a JSON-RPC request via HTTP POST."""
        if not self.session or not self._endpoint:
            raise RuntimeError("Not connected")

        self._request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": params
        }

        async with self.session.post(self._endpoint, json=request) as response:
            if response.status != 200:
                raise RuntimeError(f"Request failed: {response.status}")

            result = await response.json()

        if "error" in result:
            error = result["error"]
            raise RuntimeError(f"MCP Error: {error.get('message', error)}")

        return result.get("result", {})

    async def notify(self, method: str, params: Dict[str, Any]):
        """Send a JSON-RPC notification via HTTP POST."""
        if not self.session or not self._endpoint:
            raise RuntimeError("Not connected")

        notification = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        }

        async with self.session.post(self._endpoint, json=notification):
            pass  # Notifications don't expect a response

    async def close(self):
        """Close the HTTP session."""
        if self.session:
            await self.session.close()
            self.session = None


async def create_client(target: str, transport_type: TransportType) -> BaseMCPTransport:
    """
    Factory function to create an appropriate MCP transport.

    Args:
        target: Target specification
            - For STDIO: "python server.py" or command with args
            - For SSE: "https://example.com/sse"
        transport_type: Type of transport to use

    Returns:
        Connected MCP transport instance
    """
    if transport_type == TransportType.STDIO:
        # Parse command and arguments
        parts = target.split()
        if not parts:
            raise ValueError("Empty command for STDIO transport")

        command = parts[0]
        args = parts[1:]

        transport = StdioTransport(command, args)
        await transport.connect()
        return transport

    elif transport_type == TransportType.SSE:
        transport = SSETransport(target)
        await transport.connect()
        return transport

    else:
        raise ValueError(f"Unsupported transport type: {transport_type}")


def infer_transport_type(target: str) -> TransportType:
    """
    Infer transport type from target string.

    Args:
        target: Target specification

    Returns:
        Inferred TransportType
    """
    if target.startswith(("http://", "https://")):
        return TransportType.SSE
    elif target.startswith("stdio"):
        return TransportType.STDIO
    else:
        # Assume it's a command for STDIO
        return TransportType.STDIO
