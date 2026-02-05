"""
Dangerous Operation Analysis for AGENT-034 False Positive Reduction.

This module analyzes tool functions to determine if string parameters
flow to dangerous operations (exec, subprocess, SQL, etc.).

Only trigger AGENT-034 when:
1. Function has @tool decorator
2. Function accepts str/Any parameter
3. Parameter is actually used in dangerous operation
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple


class DangerousOperationType(Enum):
    """Classification of dangerous operations."""
    SHELL_EXECUTION = "shell_execution"
    CODE_EXECUTION = "code_execution"
    SQL_OPERATION = "sql_operation"
    FILE_WRITE = "file_write"
    NETWORK_REQUEST = "network_request"
    NONE = "none"


@dataclass
class DangerousOperationResult:
    """Result of dangerous operation analysis."""
    has_dangerous_operation: bool
    operation_type: DangerousOperationType
    operation_function: str
    param_used_in_operation: bool
    confidence: float
    reason: str


# Functions that execute untrusted input dangerously
DANGEROUS_FUNCTIONS: Dict[str, Tuple[DangerousOperationType, float]] = {
    # Shell execution (critical)
    'subprocess.run': (DangerousOperationType.SHELL_EXECUTION, 0.90),
    'subprocess.Popen': (DangerousOperationType.SHELL_EXECUTION, 0.90),
    'subprocess.call': (DangerousOperationType.SHELL_EXECUTION, 0.90),
    'subprocess.check_output': (DangerousOperationType.SHELL_EXECUTION, 0.90),
    'os.system': (DangerousOperationType.SHELL_EXECUTION, 0.95),
    'os.popen': (DangerousOperationType.SHELL_EXECUTION, 0.90),
    'os.spawn': (DangerousOperationType.SHELL_EXECUTION, 0.85),
    # Code execution (critical)
    'eval': (DangerousOperationType.CODE_EXECUTION, 0.95),
    'exec': (DangerousOperationType.CODE_EXECUTION, 0.95),
    'compile': (DangerousOperationType.CODE_EXECUTION, 0.80),
    '__import__': (DangerousOperationType.CODE_EXECUTION, 0.75),
    # SQL operations (high)
    'cursor.execute': (DangerousOperationType.SQL_OPERATION, 0.85),
    'connection.execute': (DangerousOperationType.SQL_OPERATION, 0.85),
    'session.execute': (DangerousOperationType.SQL_OPERATION, 0.85),
    'engine.execute': (DangerousOperationType.SQL_OPERATION, 0.85),
    # File write (medium-high)
    'open': (DangerousOperationType.FILE_WRITE, 0.60),
}

# Patterns to detect dangerous operations generically
DANGEROUS_PATTERNS: List[Tuple[re.Pattern, DangerousOperationType, float]] = [
    # SQL with string interpolation
    (re.compile(r'\.execute\s*\('), DangerousOperationType.SQL_OPERATION, 0.70),
    # File write modes
    (re.compile(r'open\s*\([^)]*["\']w["\']'), DangerousOperationType.FILE_WRITE, 0.70),
    (re.compile(r'\.write\s*\('), DangerousOperationType.FILE_WRITE, 0.65),
    (re.compile(r'\.write_text\s*\('), DangerousOperationType.FILE_WRITE, 0.70),
    (re.compile(r'\.write_bytes\s*\('), DangerousOperationType.FILE_WRITE, 0.70),
]

# Safe tool function patterns - these should NOT trigger AGENT-034
SAFE_TOOL_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # Read-only operations
    (re.compile(r'^get_\w+$'), "Getter function"),
    (re.compile(r'^fetch_\w+$'), "Fetch function"),
    (re.compile(r'^list_\w+$'), "List function"),
    (re.compile(r'^search_\w+$'), "Search function"),
    (re.compile(r'^find_\w+$'), "Find function"),
    (re.compile(r'^query_\w+$'), "Query function (read-only)"),
    (re.compile(r'^read_\w+$'), "Read function"),
    (re.compile(r'^load_\w+$'), "Load function"),
    (re.compile(r'^describe_\w+$'), "Describe function"),
    (re.compile(r'^lookup_\w+$'), "Lookup function"),
    (re.compile(r'^check_\w+$'), "Check function"),
    # Validation/parsing (not dangerous by themselves)
    (re.compile(r'^validate_\w+$'), "Validation function"),
    (re.compile(r'^parse_\w+$'), "Parse function"),
    (re.compile(r'^format_\w+$'), "Format function"),
    (re.compile(r'^convert_\w+$'), "Convert function"),
    (re.compile(r'^transform_\w+$'), "Transform function"),
    # Calculation/computation
    (re.compile(r'^calculate_\w+$'), "Calculate function"),
    (re.compile(r'^compute_\w+$'), "Compute function"),
    (re.compile(r'^count_\w+$'), "Count function"),
    # Display/show
    (re.compile(r'^show_\w+$'), "Show function"),
    (re.compile(r'^display_\w+$'), "Display function"),
    (re.compile(r'^print_\w+$'), "Print function"),
]


def is_safe_tool_pattern(func_name: str) -> Tuple[bool, str]:
    """
    Check if function name matches a safe tool pattern.

    Args:
        func_name: Name of the tool function

    Returns:
        Tuple of (is_safe, reason)
    """
    for pattern, description in SAFE_TOOL_PATTERNS:
        if pattern.match(func_name):
            return (True, description)
    return (False, "")


def _param_flows_to_dangerous_call(
    func_body: str,
    param_name: str,
    dangerous_func: str
) -> Tuple[bool, float]:
    """
    Simple data flow analysis to check if parameter flows to dangerous call.

    This is a heuristic-based approach:
    1. Check if param appears in the dangerous function call
    2. Check if param is used in string formatting near the call
    3. Check if param is assigned to a variable used in the call

    Args:
        func_body: Function body as string
        param_name: Name of the parameter to track
        dangerous_func: Name of the dangerous function

    Returns:
        Tuple of (flows_to_call, confidence)
    """
    # Direct usage in dangerous call
    # Pattern: dangerous_func(...param_name...)
    direct_pattern = re.compile(
        rf'{re.escape(dangerous_func)}\s*\([^)]*\b{re.escape(param_name)}\b[^)]*\)'
    )
    if direct_pattern.search(func_body):
        return (True, 0.95)

    # String formatting with param near dangerous call
    # Pattern: f"...{param_name}..." or format(...param_name...)
    fstring_pattern = re.compile(
        rf'f["\'][^"\']*\{{\s*{re.escape(param_name)}\s*\}}[^"\']*["\']'
    )
    format_pattern = re.compile(
        rf'\.format\s*\([^)]*\b{re.escape(param_name)}\b[^)]*\)'
    )

    if fstring_pattern.search(func_body) or format_pattern.search(func_body):
        # Check if the formatted string is near dangerous call
        if dangerous_func in func_body:
            return (True, 0.85)

    # Parameter concatenation
    # Pattern: param_name + "..." or "..." + param_name
    concat_pattern = re.compile(
        rf'(\b{re.escape(param_name)}\b\s*\+|\+\s*\b{re.escape(param_name)}\b)'
    )
    if concat_pattern.search(func_body) and dangerous_func in func_body:
        return (True, 0.80)

    # Variable assignment tracking (simple)
    # Pattern: var = param_name; then var used in dangerous call
    assign_pattern = re.compile(
        rf'(\w+)\s*=\s*{re.escape(param_name)}\b'
    )
    for match in assign_pattern.finditer(func_body):
        assigned_var = match.group(1)
        # Check if assigned variable flows to dangerous call
        var_in_call = re.compile(
            rf'{re.escape(dangerous_func)}\s*\([^)]*\b{re.escape(assigned_var)}\b'
        )
        if var_in_call.search(func_body):
            return (True, 0.75)

    return (False, 0.0)


def analyze_tool_for_dangerous_operations(
    func_name: str,
    func_body: str,
    param_names: List[str],
    param_types: Optional[List[str]] = None,
) -> DangerousOperationResult:
    """
    Analyze if a tool function's string parameters flow to dangerous operations.

    Args:
        func_name: Name of the function
        func_body: Function body as string (use ast.unparse or similar)
        param_names: List of parameter names
        param_types: List of parameter types (str, Any, etc.) - optional

    Returns:
        DangerousOperationResult indicating whether AGENT-034 should fire
    """
    # Step 1: Check if function matches safe patterns
    is_safe, safe_reason = is_safe_tool_pattern(func_name)
    if is_safe:
        return DangerousOperationResult(
            has_dangerous_operation=False,
            operation_type=DangerousOperationType.NONE,
            operation_function="",
            param_used_in_operation=False,
            confidence=0.0,
            reason=f"Safe tool pattern: {safe_reason}"
        )

    # Step 2: Check for dangerous operations in function body
    for dangerous_func, (op_type, base_conf) in DANGEROUS_FUNCTIONS.items():
        if dangerous_func in func_body:
            # Step 3: Check if any parameter flows to this operation
            for param_name in param_names:
                flows, flow_conf = _param_flows_to_dangerous_call(
                    func_body, param_name, dangerous_func
                )
                if flows:
                    # Calculate combined confidence
                    confidence = base_conf * flow_conf
                    return DangerousOperationResult(
                        has_dangerous_operation=True,
                        operation_type=op_type,
                        operation_function=dangerous_func,
                        param_used_in_operation=True,
                        confidence=confidence,
                        reason=f"Parameter '{param_name}' flows to {dangerous_func}"
                    )

    # Step 4: Check for dangerous patterns
    for pattern, op_type, base_conf in DANGEROUS_PATTERNS:
        if pattern.search(func_body):
            # Check if any parameter flows to this pattern
            for param_name in param_names:
                # Simple check: param appears near the pattern
                param_near_pattern = re.compile(
                    rf'\b{re.escape(param_name)}\b.{{0,50}}{pattern.pattern}|'
                    rf'{pattern.pattern}.{{0,50}}\b{re.escape(param_name)}\b',
                    re.DOTALL
                )
                if param_near_pattern.search(func_body):
                    return DangerousOperationResult(
                        has_dangerous_operation=True,
                        operation_type=op_type,
                        operation_function=pattern.pattern,
                        param_used_in_operation=True,
                        confidence=base_conf * 0.8,
                        reason=f"Parameter '{param_name}' used near dangerous pattern"
                    )

    # No dangerous operations found
    return DangerousOperationResult(
        has_dangerous_operation=False,
        operation_type=DangerousOperationType.NONE,
        operation_function="",
        param_used_in_operation=False,
        confidence=0.0,
        reason="No dangerous operations detected with parameter flow"
    )


def should_flag_tool_input(
    func_name: str,
    func_body: str,
    param_names: List[str],
    param_types: Optional[List[str]] = None,
    has_validation: bool = False,
) -> Tuple[bool, float, str]:
    """
    Determine if a tool should be flagged for AGENT-034.

    This is the main entry point for AGENT-034 detection logic.

    Args:
        func_name: Name of the tool function
        func_body: Function body as string
        param_names: List of parameter names
        param_types: Optional list of parameter types
        has_validation: Whether the function has input validation

    Returns:
        Tuple of (should_flag, confidence, reason)
    """
    # If function has validation, reduce concern
    validation_factor = 0.5 if has_validation else 1.0

    # Analyze for dangerous operations
    result = analyze_tool_for_dangerous_operations(
        func_name=func_name,
        func_body=func_body,
        param_names=param_names,
        param_types=param_types,
    )

    if not result.has_dangerous_operation:
        return (False, 0.0, result.reason)

    # Apply validation factor
    final_confidence = result.confidence * validation_factor

    # Only flag if confidence is high enough
    if final_confidence < 0.50:
        return (False, final_confidence, f"{result.reason} (confidence below threshold)")

    return (True, final_confidence, result.reason)
