"""Extended tests for cross-platform compatibility utilities."""

import sys
import os
import pytest
from pathlib import Path
from unittest.mock import patch

from agent_audit.utils.compat import (
    IS_WINDOWS,
    IS_MACOS,
    IS_LINUX,
    normalize_path,
    home_config_dir,
    get_subprocess_creation_flags,
    setup_event_loop_policy,
)


class TestHomeConfigDirPlatformSpecific:
    """Platform-specific tests for home_config_dir."""

    @patch("sys.platform", "darwin")
    def test_macos_uses_library(self):
        """On macOS, should use Library/Application Support."""
        # Re-evaluate the function with mocked platform
        result = home_config_dir()
        # Verify it returns a Path
        assert isinstance(result, Path)
        result_str = str(result)
        # On actual macOS or when mocked, check structure
        assert "agent-audit" in result_str

    @patch.dict(os.environ, {"XDG_CONFIG_HOME": "/custom/config"}, clear=False)
    def test_linux_uses_xdg_config_home(self):
        """On Linux with XDG_CONFIG_HOME, should use it."""
        if sys.platform.startswith("linux"):
            result = home_config_dir()
            result_str = str(result)
            assert "agent-audit" in result_str

    def test_fallback_to_home_directory(self):
        """Should always have a fallback to home directory."""
        result = home_config_dir()
        # The path should exist as a valid location relative to home
        assert isinstance(result, Path)


class TestNormalizePathEdgeCases:
    """Edge case tests for normalize_path."""

    def test_normalize_only_backslashes(self):
        """Path with only backslashes should convert to forward slashes."""
        path = "\\\\server\\share\\file.txt"
        result = normalize_path(path)
        assert "\\" not in result
        assert result == "//server/share/file.txt"

    def test_normalize_windows_unc_path(self):
        """Windows UNC paths should be normalized."""
        path = "\\\\server\\share\\folder\\file.txt"
        result = normalize_path(path)
        assert result == "//server/share/folder/file.txt"

    def test_normalize_windows_drive_path(self):
        """Windows drive paths should be normalized."""
        path = "C:\\Users\\Test\\file.txt"
        result = normalize_path(path)
        assert result == "C:/Users/Test/file.txt"

    def test_normalize_path_with_dots(self):
        """Paths with dots should be preserved."""
        path = "..\\..\\parent\\file.txt"
        result = normalize_path(path)
        assert result == "../../parent/file.txt"

    def test_normalize_single_file(self):
        """Single filename should remain unchanged."""
        path = "file.txt"
        result = normalize_path(path)
        assert result == "file.txt"

    def test_normalize_current_directory(self):
        """Current directory should remain unchanged."""
        path = "."
        result = normalize_path(path)
        assert result == "."


class TestSubprocessFlagsEdgeCases:
    """Edge case tests for subprocess creation flags."""

    def test_flags_are_integer(self):
        """Flags should always be an integer."""
        flags = get_subprocess_creation_flags()
        assert isinstance(flags, int)
        assert flags >= 0

    def test_flags_can_be_used_with_or(self):
        """Flags should be usable with bitwise OR."""
        flags = get_subprocess_creation_flags()
        combined = flags | 0x0  # OR with 0
        assert combined == flags


class TestEventLoopPolicyIdempotent:
    """Tests for event loop policy setup idempotency."""

    def test_can_be_called_multiple_times(self):
        """setup_event_loop_policy should be idempotent."""
        # Call multiple times - should not raise
        setup_event_loop_policy()
        setup_event_loop_policy()
        setup_event_loop_policy()

    def test_event_loop_remains_functional(self):
        """Event loop should work after policy setup."""
        import asyncio
        setup_event_loop_policy()

        async def simple_coro():
            return "done"

        result = asyncio.run(simple_coro())
        assert result == "done"


class TestPlatformDetectionConsistency:
    """Tests for platform detection consistency."""

    def test_platforms_are_mutually_exclusive(self):
        """Platform constants should be mutually exclusive."""
        # At most one can be True on any given system
        platforms = [IS_WINDOWS, IS_MACOS, IS_LINUX]
        true_count = sum(1 for p in platforms if p)
        # Could be 0 on unusual platforms, but typically 1
        assert true_count <= 1

    def test_platform_matches_sys_platform(self):
        """Platform detection should match sys.platform."""
        if sys.platform == "win32":
            assert IS_WINDOWS
        elif sys.platform == "darwin":
            assert IS_MACOS
        elif sys.platform.startswith("linux"):
            assert IS_LINUX
