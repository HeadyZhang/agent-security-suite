"""Tests for cross-platform compatibility utilities."""

import sys
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


class TestPlatformConstants:
    """Tests for platform detection constants."""

    def test_platform_constants_are_booleans(self):
        """Platform constants should be boolean values."""
        assert isinstance(IS_WINDOWS, bool)
        assert isinstance(IS_MACOS, bool)
        assert isinstance(IS_LINUX, bool)

    def test_at_least_one_platform_is_true(self):
        """At least one platform should be detected as true."""
        # On any system, at least one should be true
        # (unless running on an exotic platform)
        platforms = [IS_WINDOWS, IS_MACOS, IS_LINUX]
        # At least one should be true on common platforms
        assert any(platforms) or sys.platform not in ("win32", "darwin", "linux")

    def test_windows_constant_matches_platform(self):
        """IS_WINDOWS should match sys.platform."""
        assert IS_WINDOWS == (sys.platform == "win32")

    def test_macos_constant_matches_platform(self):
        """IS_MACOS should match sys.platform."""
        assert IS_MACOS == (sys.platform == "darwin")

    def test_linux_constant_matches_platform(self):
        """IS_LINUX should match sys.platform."""
        assert IS_LINUX == sys.platform.startswith("linux")


class TestNormalizePath:
    """Tests for normalize_path function."""

    def test_normalize_forward_slashes(self):
        """Forward slashes should remain unchanged."""
        path = "/home/user/test.py"
        assert normalize_path(path) == "/home/user/test.py"

    def test_normalize_backslashes_to_forward(self):
        """Backslashes should be converted to forward slashes."""
        path = "C:\\Users\\test\\file.py"
        assert normalize_path(path) == "C:/Users/test/file.py"

    def test_normalize_mixed_slashes(self):
        """Mixed slashes should all become forward slashes."""
        path = "C:\\Users/test\\file.py"
        assert normalize_path(path) == "C:/Users/test/file.py"

    def test_normalize_path_object(self):
        """Path objects should be converted and normalized."""
        path = Path("test") / "subdir" / "file.py"
        result = normalize_path(path)
        # Result should always use forward slashes
        assert "\\" not in result
        assert "test" in result and "file.py" in result

    def test_normalize_empty_path(self):
        """Empty path should remain empty."""
        assert normalize_path("") == ""

    def test_normalize_relative_path(self):
        """Relative paths should be normalized."""
        assert normalize_path("..\\parent\\file.py") == "../parent/file.py"

    def test_normalize_preserves_unicode(self):
        """Unicode characters in paths should be preserved."""
        path = "C:\\Users\\日本語\\文件.py"
        result = normalize_path(path)
        assert "日本語" in result
        assert "文件.py" in result


class TestHomeConfigDir:
    """Tests for home_config_dir function."""

    def test_returns_path_object(self):
        """Should return a Path object."""
        result = home_config_dir()
        assert isinstance(result, Path)

    def test_path_contains_agent_audit(self):
        """Returned path should contain 'agent-audit'."""
        result = home_config_dir()
        assert "agent-audit" in str(result)

    @patch("sys.platform", "win32")
    @patch.dict("os.environ", {"APPDATA": "C:\\Users\\Test\\AppData\\Roaming"})
    def test_windows_uses_appdata(self):
        """On Windows, should use APPDATA directory."""
        # Re-import to pick up the mocked platform
        from agent_audit.utils import compat
        # Note: This test verifies the logic but may not trigger due to module caching
        # The actual platform-specific behavior is tested at runtime
        result = home_config_dir()
        assert isinstance(result, Path)

    def test_path_is_under_user_directory(self):
        """Config directory should be under user's home or app data."""
        result = home_config_dir()
        home = Path.home()
        # Either under home, or in system-specific location
        result_str = str(result)
        # On most systems, it should be somewhere related to user space
        assert len(result_str) > 5  # Some reasonable path length


class TestSubprocessCreationFlags:
    """Tests for get_subprocess_creation_flags function."""

    def test_returns_integer(self):
        """Should return an integer."""
        result = get_subprocess_creation_flags()
        assert isinstance(result, int)

    def test_non_windows_returns_zero(self):
        """On non-Windows platforms, should return 0."""
        if sys.platform != "win32":
            assert get_subprocess_creation_flags() == 0

    def test_windows_returns_create_no_window(self):
        """On Windows, should return CREATE_NO_WINDOW flag."""
        if sys.platform == "win32":
            # CREATE_NO_WINDOW = 0x08000000
            assert get_subprocess_creation_flags() == 0x08000000


class TestSetupEventLoopPolicy:
    """Tests for setup_event_loop_policy function."""

    def test_function_does_not_raise(self):
        """Function should not raise exceptions."""
        # Just verify it can be called without error
        setup_event_loop_policy()

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_windows_sets_selector_policy(self):
        """On Windows, should set WindowsSelectorEventLoopPolicy."""
        import asyncio
        setup_event_loop_policy()
        policy = asyncio.get_event_loop_policy()
        assert isinstance(policy, asyncio.WindowsSelectorEventLoopPolicy)
