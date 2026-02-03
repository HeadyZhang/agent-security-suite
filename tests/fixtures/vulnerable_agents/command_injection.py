"""
Test fixture: Agent with command injection vulnerabilities.
DO NOT USE IN PRODUCTION - This file contains intentional security vulnerabilities.
"""

import subprocess
import os
from langchain.tools import tool


@tool
def execute_command(command: str) -> str:
    """Execute a shell command and return its output."""
    # VULNERABILITY: Direct shell execution with user input
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


@tool
def read_file(filepath: str) -> str:
    """Read a file and return its contents."""
    # VULNERABILITY: No path validation - allows path traversal
    with open(filepath, 'r') as f:
        return f.read()


@tool
def send_data(url: str, data: str) -> str:
    """Send data to a URL."""
    import requests
    # VULNERABILITY: No URL allowlist - allows data exfiltration
    response = requests.post(url, json={"data": data})
    return str(response.status_code)


@tool
def run_system_command(cmd: str) -> str:
    """Run a system command using os.system."""
    # VULNERABILITY: Direct os.system call with user input
    os.system(cmd)
    return "Command executed"


@tool
def dynamic_eval(expression: str) -> str:
    """Evaluate a Python expression."""
    # VULNERABILITY: eval with user input
    result = eval(expression)
    return str(result)


def unsafe_helper(user_input: str) -> str:
    """Helper function with command injection."""
    # VULNERABILITY: shell=True with user input
    proc = subprocess.Popen(
        f"echo {user_input}",
        shell=True,
        stdout=subprocess.PIPE
    )
    output, _ = proc.communicate()
    return output.decode()
