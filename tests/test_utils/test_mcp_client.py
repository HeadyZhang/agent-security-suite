"""Tests for MCP protocol client."""

import pytest
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

from agent_audit.utils.mcp_client import (
    TransportType,
    BaseMCPTransport,
    StdioTransport,
    SSETransport,
    create_client,
    infer_transport_type,
)


class TestTransportType:
    """Tests for TransportType enum."""

    def test_transport_types_exist(self):
        """All expected transport types should exist."""
        assert TransportType.STDIO.value == "stdio"
        assert TransportType.SSE.value == "sse"
        assert TransportType.STREAMABLE_HTTP.value == "streamable_http"

    def test_transport_type_values(self):
        """Transport type values should be strings."""
        for transport_type in TransportType:
            assert isinstance(transport_type.value, str)


class TestInferTransportType:
    """Tests for transport type inference."""

    def test_infer_http_url_as_sse(self):
        """HTTP URLs should infer SSE transport."""
        assert infer_transport_type("http://example.com/sse") == TransportType.SSE

    def test_infer_https_url_as_sse(self):
        """HTTPS URLs should infer SSE transport."""
        assert infer_transport_type("https://example.com/sse") == TransportType.SSE

    def test_infer_stdio_prefix_as_stdio(self):
        """'stdio' prefix should infer STDIO transport."""
        assert infer_transport_type("stdio:///path") == TransportType.STDIO

    def test_infer_command_as_stdio(self):
        """Commands should infer STDIO transport."""
        assert infer_transport_type("python server.py") == TransportType.STDIO

    def test_infer_node_command_as_stdio(self):
        """Node commands should infer STDIO transport."""
        assert infer_transport_type("node server.js") == TransportType.STDIO

    def test_infer_npx_command_as_stdio(self):
        """npx commands should infer STDIO transport."""
        assert infer_transport_type("npx mcp-server") == TransportType.STDIO


class TestStdioTransport:
    """Tests for StdioTransport class."""

    def test_initialization(self):
        """StdioTransport should initialize with command and args."""
        transport = StdioTransport("python", ["server.py"])

        assert transport.command == "python"
        assert transport.args == ["server.py"]
        assert transport.env is None
        assert transport.process is None

    def test_initialization_with_env(self):
        """StdioTransport should accept environment variables."""
        transport = StdioTransport("python", ["server.py"], env={"KEY": "value"})

        assert transport.env == {"KEY": "value"}

    def test_default_args_is_empty_list(self):
        """Default args should be empty list."""
        transport = StdioTransport("python")

        assert transport.args == []

    @pytest.mark.asyncio
    async def test_connect_creates_process(self):
        """connect() should create subprocess."""
        transport = StdioTransport("echo", ["hello"])

        # Mock the subprocess creation
        mock_process = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stdout.readline = AsyncMock(return_value=b"")
        mock_process.stdin = MagicMock()

        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=mock_process)):
            await transport.connect()

            assert transport.process is not None

            # Clean up
            transport._reader_task.cancel()

    @pytest.mark.asyncio
    async def test_close_terminates_process(self):
        """close() should terminate the subprocess."""
        transport = StdioTransport("echo", ["hello"])

        # Mock process
        mock_process = MagicMock()
        mock_process.terminate = MagicMock()
        mock_process.wait = AsyncMock()
        transport.process = mock_process

        # Create a real asyncio task that can be cancelled
        async def dummy_reader():
            await asyncio.sleep(100)

        transport._reader_task = asyncio.create_task(dummy_reader())

        await transport.close()

        mock_process.terminate.assert_called_once()

    def test_request_id_increments(self):
        """Request ID should start at 0."""
        transport = StdioTransport("python")

        assert transport._request_id == 0

    @pytest.mark.asyncio
    async def test_send_raises_when_not_connected(self):
        """send() should raise RuntimeError when not connected."""
        transport = StdioTransport("python")

        with pytest.raises(RuntimeError, match="Not connected"):
            await transport.send("method", {})

    @pytest.mark.asyncio
    async def test_notify_raises_when_not_connected(self):
        """notify() should raise RuntimeError when not connected."""
        transport = StdioTransport("python")

        with pytest.raises(RuntimeError, match="Not connected"):
            await transport.notify("method", {})


class TestSSETransport:
    """Tests for SSETransport class."""

    def test_initialization(self):
        """SSETransport should initialize with URL."""
        transport = SSETransport("https://example.com/sse")

        assert transport.url == "https://example.com/sse"
        assert transport.session is None
        assert transport._endpoint is None

    def test_request_id_starts_at_zero(self):
        """Request ID should start at 0."""
        transport = SSETransport("https://example.com/sse")

        assert transport._request_id == 0

    @pytest.mark.asyncio
    async def test_send_raises_when_not_connected(self):
        """send() should raise RuntimeError when not connected."""
        transport = SSETransport("https://example.com/sse")

        with pytest.raises(RuntimeError, match="Not connected"):
            await transport.send("method", {})

    @pytest.mark.asyncio
    async def test_notify_raises_when_not_connected(self):
        """notify() should raise RuntimeError when not connected."""
        transport = SSETransport("https://example.com/sse")

        with pytest.raises(RuntimeError, match="Not connected"):
            await transport.notify("method", {})

    @pytest.mark.asyncio
    async def test_close_when_no_session(self):
        """close() should handle no session gracefully."""
        transport = SSETransport("https://example.com/sse")

        await transport.close()  # Should not raise

        assert transport.session is None


class TestCreateClient:
    """Tests for create_client factory function."""

    @pytest.mark.asyncio
    async def test_create_client_raises_on_empty_command(self):
        """Should raise ValueError for empty STDIO command."""
        with pytest.raises(ValueError, match="Empty command"):
            await create_client("", TransportType.STDIO)

    @pytest.mark.asyncio
    async def test_create_client_raises_on_unsupported_type(self):
        """Should raise ValueError for unsupported transport type."""
        with pytest.raises(ValueError, match="Unsupported transport type"):
            await create_client("target", TransportType.STREAMABLE_HTTP)

    @pytest.mark.asyncio
    async def test_create_stdio_client_parses_command(self):
        """Should parse command and args for STDIO transport."""
        mock_process = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stdout.readline = AsyncMock(return_value=b"")
        mock_process.stdin = MagicMock()

        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=mock_process)):
            transport = await create_client("python server.py --arg", TransportType.STDIO)

            assert isinstance(transport, StdioTransport)
            assert transport.command == "python"
            assert transport.args == ["server.py", "--arg"]

            # Clean up
            transport._reader_task.cancel()


class TestBaseMCPTransport:
    """Tests for BaseMCPTransport abstract class."""

    def test_is_abstract(self):
        """BaseMCPTransport should be abstract."""
        # Cannot instantiate directly
        with pytest.raises(TypeError):
            BaseMCPTransport()

    def test_has_required_methods(self):
        """Should have all required abstract methods."""
        assert hasattr(BaseMCPTransport, "connect")
        assert hasattr(BaseMCPTransport, "send")
        assert hasattr(BaseMCPTransport, "notify")
        assert hasattr(BaseMCPTransport, "close")


class TestWindowsCompatibility:
    """Tests for Windows compatibility features."""

    def test_creation_flags_constant_exists(self):
        """CREATE_NO_WINDOW constant should exist."""
        from agent_audit.utils.mcp_client import _CREATE_NO_WINDOW
        assert isinstance(_CREATE_NO_WINDOW, int)

    def test_is_windows_constant_exists(self):
        """IS_WINDOWS constant should exist."""
        from agent_audit.utils.mcp_client import _IS_WINDOWS
        assert isinstance(_IS_WINDOWS, bool)
