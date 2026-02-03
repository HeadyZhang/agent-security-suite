"""
Test fixture: Safe agent with no vulnerabilities.
Used for false positive testing.
"""

import shlex
import subprocess
from typing import List
from langchain.tools import tool


ALLOWED_COMMANDS = ["ls", "pwd", "date", "whoami"]


@tool
def safe_execute(command: str) -> str:
    """Execute a whitelisted command safely."""
    # Safe: Command whitelist
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f"Command not allowed: {command}")

    # Safe: No shell=True, command is validated
    result = subprocess.run([command], capture_output=True, text=True)
    return result.stdout


@tool
def safe_read_file(filepath: str) -> str:
    """Read a file from allowed directory."""
    import os

    # Safe: Path validation
    allowed_dir = "/app/data"
    abs_path = os.path.abspath(filepath)

    if not abs_path.startswith(allowed_dir):
        raise ValueError("Access denied: Path outside allowed directory")

    with open(abs_path, 'r') as f:
        return f.read()


@tool
def calculate(expression: str) -> str:
    """Safely evaluate a mathematical expression."""
    import ast
    import operator

    # Safe: AST-based safe evaluation
    allowed_operators = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
    }

    def eval_expr(node):
        if isinstance(node, ast.Num):
            return node.n
        elif isinstance(node, ast.BinOp):
            left = eval_expr(node.left)
            right = eval_expr(node.right)
            op = allowed_operators.get(type(node.op))
            if op is None:
                raise ValueError("Operator not allowed")
            return op(left, right)
        else:
            raise ValueError("Invalid expression")

    tree = ast.parse(expression, mode='eval')
    return str(eval_expr(tree.body))


def get_config_value(key: str) -> str:
    """Get configuration from environment."""
    import os
    # Safe: Using environment variables, not hardcoded
    return os.environ.get(key, "")
