"""Cross-platform compatibility utilities.

This module provides platform detection and path handling utilities
to ensure the tool works correctly on Windows, macOS, and Linux.
"""

import sys
from pathlib import Path
from typing import Union

# Platform detection constants
IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")


def normalize_path(path: Union[str, Path]) -> str:
    """
    Normalize a path to use forward slashes consistently.

    This ensures that file paths stored in findings and reports
    use consistent forward slashes across all platforms, making
    output deterministic and comparable.

    Args:
        path: Path to normalize (string or Path object)

    Returns:
        Normalized path string with forward slashes
    """
    path_str = str(path)
    # Always use forward slashes for consistency in outputs
    return path_str.replace("\\", "/")


def home_config_dir() -> Path:
    """
    Get the appropriate configuration directory for the current platform.

    Returns:
        - Windows: %APPDATA%/agent-audit
        - macOS: ~/Library/Application Support/agent-audit
        - Linux: ~/.config/agent-audit

    Falls back to ~/.agent-audit if the platform-specific directory
    cannot be determined.
    """
    if IS_WINDOWS:
        # Use APPDATA on Windows
        import os
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "agent-audit"
        # Fallback to home directory
        return Path.home() / ".agent-audit"

    elif IS_MACOS:
        # Use Library/Application Support on macOS
        return Path.home() / "Library" / "Application Support" / "agent-audit"

    else:
        # Use XDG_CONFIG_HOME on Linux, fallback to ~/.config
        import os
        xdg_config = os.environ.get("XDG_CONFIG_HOME")
        if xdg_config:
            return Path(xdg_config) / "agent-audit"
        return Path.home() / ".config" / "agent-audit"


def get_subprocess_creation_flags() -> int:
    """
    Get the appropriate subprocess creation flags for the current platform.

    On Windows, returns CREATE_NO_WINDOW to prevent console windows from
    appearing when running background processes. On other platforms, returns 0.

    Returns:
        Creation flags for subprocess.Popen or asyncio.create_subprocess_exec
    """
    if IS_WINDOWS:
        # CREATE_NO_WINDOW = 0x08000000
        # Prevents console window from appearing
        return 0x08000000
    return 0


def setup_event_loop_policy():
    """
    Configure the asyncio event loop policy for the current platform.

    On Windows, sets WindowsSelectorEventLoopPolicy to avoid issues with
    ProactorEventLoop and subprocesses. This should be called early in
    the application startup.
    """
    if IS_WINDOWS:
        import asyncio
        # WindowsSelectorEventLoopPolicy is more compatible with subprocess operations
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
