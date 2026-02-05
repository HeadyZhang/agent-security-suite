"""
Single-step ENV data flow tracer.

This module tracks variables assigned from environment reads (os.getenv,
os.environ, process.env) within the same file scope. When f-strings or
template literals reference env-sourced variables, we reduce confidence.

Limitations:
- Only tracks same-file, same-scope
- Only single-step indirect (no cross-function/cross-module tracking)
- This is a "best effort" heuristic, not guaranteed complete

Example:
  DB_PASS = os.getenv('DB_PASS', 'postgres')  <- identifies DB_PASS as env-sourced
  url = f'postgresql://{DB_USER}:{DB_PASS}@...'  <- DB_PASS in interpolation -> reduce confidence

v0.8.0: Initial implementation for AGENT-004 false positive reduction.
"""

from __future__ import annotations

import ast
import re
import logging
from typing import Optional, Set

logger = logging.getLogger(__name__)


class EnvTracer:
    """
    Single-step ENV data flow tracer.

    Traces variables that are assigned from environment variable reads
    to help identify false positives where interpolated values actually
    come from environment variables rather than hardcoded credentials.
    """

    # Python ENV_READ function patterns
    PYTHON_ENV_GETTERS = {
        "os.getenv",
        "os.environ.get",
        "os.environ",
    }

    def trace_env_vars_python(self, source: str) -> Set[str]:
        """
        Use Python AST to trace env-sourced variable names.

        Args:
            source: Python source code

        Returns:
            Set of variable names that are assigned from env reads
            e.g., {"DB_USER", "DB_PASS", "API_KEY"}
        """
        env_vars: Set[str] = set()

        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            logger.debug(f"EnvTracer: AST parse failed: {e}")
            return env_vars

        for node in ast.walk(tree):
            # Pattern 1: DB_PASS = os.getenv('DB_PASS', 'postgres')
            # Pattern 2: DB_PASS = os.environ['DB_PASS']
            # Pattern 3: DB_PASS = os.environ.get('DB_PASS', default)
            if isinstance(node, ast.Assign):
                if self._is_env_read_call(node.value):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            env_vars.add(target.id)
                            logger.debug(f"EnvTracer: Found env-sourced var: {target.id}")

            # Pattern 4: Annotated assignment: DB_PASS: str = os.getenv(...)
            if isinstance(node, ast.AnnAssign):
                if node.value and self._is_env_read_call(node.value):
                    if isinstance(node.target, ast.Name):
                        env_vars.add(node.target.id)
                        logger.debug(f"EnvTracer: Found env-sourced var: {node.target.id}")

        return env_vars

    def trace_env_vars_ts(self, source: str) -> Set[str]:
        """
        Use regex to trace TypeScript/JavaScript env-sourced variable names.

        Matches patterns:
          const DB_PASS = process.env.DB_PASS
          const { DB_USER, DB_PASS } = process.env
          let apiKey = process.env['API_KEY']

        Args:
            source: TypeScript/JavaScript source code

        Returns:
            Set of variable names that are assigned from env reads
        """
        env_vars: Set[str] = set()

        # Pattern 1: const/let/var X = process.env.Y
        pattern1 = re.compile(
            r"(?:const|let|var)\s+(\w+)\s*=\s*process\.env\.\w+",
            re.MULTILINE
        )
        for match in pattern1.finditer(source):
            env_vars.add(match.group(1))
            logger.debug(f"EnvTracer (TS): Found env-sourced var: {match.group(1)}")

        # Pattern 2: const { X, Y } = process.env
        pattern2 = re.compile(
            r"(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*=\s*process\.env",
            re.MULTILINE
        )
        for match in pattern2.finditer(source):
            # Parse destructured names (may include renaming: originalName: newName)
            names_str = match.group(1)
            for part in names_str.split(","):
                part = part.strip()
                if ":" in part:
                    # Renaming: { DB_PASS: password } -> both are env-sourced
                    orig, renamed = part.split(":", 1)
                    env_vars.add(orig.strip())
                    env_vars.add(renamed.strip())
                else:
                    if part:
                        env_vars.add(part)
            logger.debug(f"EnvTracer (TS): Found destructured env vars: {names_str}")

        # Pattern 3: const X = process.env['Y'] or process.env["Y"]
        pattern3 = re.compile(
            r"(?:const|let|var)\s+(\w+)\s*=\s*process\.env\[",
            re.MULTILINE
        )
        for match in pattern3.finditer(source):
            env_vars.add(match.group(1))
            logger.debug(f"EnvTracer (TS): Found env-sourced var: {match.group(1)}")

        # Pattern 4: Deno.env.get('KEY')
        pattern4 = re.compile(
            r"(?:const|let|var)\s+(\w+)\s*=\s*Deno\.env\.get\s*\(",
            re.MULTILINE
        )
        for match in pattern4.finditer(source):
            env_vars.add(match.group(1))
            logger.debug(f"EnvTracer (Deno): Found env-sourced var: {match.group(1)}")

        return env_vars

    def is_env_sourced_interpolation(
        self,
        value_expr: str,
        env_vars: Set[str]
    ) -> bool:
        """
        Check if f-string/template string has env-sourced interpolated variables.

        Args:
            value_expr: The string expression, could be:
              - Python f-string: f'postgresql://{DB_USER}:{DB_PASS}@...'
              - JS template literal: `postgresql://${DB_USER}:${DB_PASS}@...`
            env_vars: Set of known env-sourced variable names

        Returns:
            True if any interpolated variable is env-sourced
        """
        if not env_vars:
            return False

        # Extract Python interpolation variables: {VAR_NAME}
        # Also handles simple expressions like {DB_USER.lower()}
        py_vars: Set[str] = set()
        for match in re.finditer(r"\{(\w+)(?:\.[^}]*)?\}", value_expr):
            py_vars.add(match.group(1))

        # Extract JavaScript interpolation variables: ${VAR_NAME}
        # Also handles expressions like ${DB_USER.toLowerCase()}
        js_vars: Set[str] = set()
        for match in re.finditer(r"\$\{(\w+)(?:\.[^}]*)?\}", value_expr):
            js_vars.add(match.group(1))

        interpolated = py_vars | js_vars

        # If ANY interpolated variable is env-sourced, return True
        # This is a conservative approach - if even one var is from env,
        # the whole string is likely safe
        if interpolated & env_vars:
            logger.debug(
                f"EnvTracer: Interpolation uses env-sourced vars: "
                f"{interpolated & env_vars}"
            )
            return True

        return False

    def _is_env_read_call(self, node: ast.expr) -> bool:
        """
        Check if an AST expression node is an environment read.

        Handles:
        - os.getenv('KEY') or os.getenv('KEY', default)
        - os.environ.get('KEY') or os.environ.get('KEY', default)
        - os.environ['KEY']
        """
        # os.getenv(...)
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                # os.environ.get(...)
                if isinstance(func.value, ast.Attribute):
                    value_name = getattr(func.value.value, 'id', None)
                    value_attr = func.value.attr
                    func_attr = func.attr
                    if value_name == 'os' and value_attr == 'environ' and func_attr == 'get':
                        return True

                # os.getenv(...)
                value_name = getattr(func.value, 'id', None)
                func_attr = func.attr
                if value_name == 'os' and func_attr == 'getenv':
                    return True

        # os.environ['KEY']
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute):
                value_name = getattr(node.value.value, 'id', None)
                attr_name = node.value.attr
                if value_name == 'os' and attr_name == 'environ':
                    return True

        return False


# Module-level singleton
_tracer: Optional[EnvTracer] = None


def get_env_tracer() -> EnvTracer:
    """Get or create the EnvTracer singleton."""
    global _tracer
    if _tracer is None:
        _tracer = EnvTracer()
    return _tracer
