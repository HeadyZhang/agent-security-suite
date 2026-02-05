"""
Framework Detection for False Positive Reduction.

Identifies framework internal code patterns that commonly generate
false positives for credential detection (AGENT-004).

Key patterns:
1. Pydantic Field/BaseModel definitions
2. Framework internal paths (crewai/, langchain_core/)
3. Type annotations without actual values
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Tuple


@dataclass
class FrameworkContext:
    """Context about detected framework patterns."""
    is_framework_internal: bool
    framework_name: str
    pattern_type: str  # 'config_schema', 'internal_path', 'framework_class', 'type_annotation'
    confidence: float
    reason: str


# Framework-specific internal paths
FRAMEWORK_INTERNAL_PATHS: Dict[str, List[str]] = {
    'crewai': [
        'crewai/tools/',
        'crewai/agents/',
        'crewai/tasks/',
        'crewai/cli/',
        'crewai/memory/',
        'crewai/flow/',
        'crewai/utilities/',
        'lib/crewai/',
        'site-packages/crewai/',
    ],
    'langchain': [
        'langchain_core/tools/',
        'langchain_core/callbacks/',
        'langchain_core/retrievers/',
        'langchain_core/prompts/',
        'langchain_core/runnables/',
        'langchain/tools/',
        'langchain/agents/',
        'langchain/memory/',
        'site-packages/langchain/',
    ],
    'autogen': [
        'autogen/agentchat/',
        'autogen/oai/',
        'autogen/coding/',
        'site-packages/autogen/',
    ],
    'openai_agents': [
        'openai_agents/tools/',
        'agents/tools/',
    ],
    'llamaindex': [
        'llama_index/core/',
        'llama_index/tools/',
        'site-packages/llama_index/',
    ],
}

# Pydantic schema patterns - these are type definitions, not credentials
SCHEMA_FIELD_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    # Pydantic Field definitions
    (re.compile(r'api_key\s*:\s*(?:Optional\[)?(?:str|SecretStr)(?:\])?\s*=\s*Field\s*\('),
     'Pydantic Field definition', 0.95),
    (re.compile(r'secret\s*:\s*(?:Optional\[)?(?:str|SecretStr)(?:\])?\s*=\s*Field\s*\('),
     'Pydantic Field definition', 0.95),
    (re.compile(r'password\s*:\s*(?:Optional\[)?(?:str|SecretStr)(?:\])?\s*=\s*Field\s*\('),
     'Pydantic Field definition', 0.95),
    (re.compile(r'token\s*:\s*(?:Optional\[)?(?:str|SecretStr)(?:\])?\s*=\s*Field\s*\('),
     'Pydantic Field definition', 0.95),
    (re.compile(r'\w+_key\s*:\s*(?:Optional\[)?(?:str|SecretStr)(?:\])?\s*=\s*Field\s*\('),
     'Pydantic Field definition', 0.90),
    (re.compile(r'\w+_secret\s*:\s*(?:Optional\[)?(?:str|SecretStr)(?:\])?\s*=\s*Field\s*\('),
     'Pydantic Field definition', 0.90),

    # Type annotations without values (schema definitions)
    (re.compile(r'api_key\s*:\s*(?:Optional\[)?str(?:\])?\s*$'),
     'Type annotation only', 0.90),
    (re.compile(r'secret\s*:\s*(?:Optional\[)?str(?:\])?\s*$'),
     'Type annotation only', 0.90),
    (re.compile(r'password\s*:\s*(?:Optional\[)?str(?:\])?\s*$'),
     'Type annotation only', 0.90),
    (re.compile(r'token\s*:\s*(?:Optional\[)?str(?:\])?\s*$'),
     'Type annotation only', 0.85),

    # Type hints with None default
    (re.compile(r'api_key\s*:\s*(?:Optional\[)?str(?:\])?\s*=\s*None'),
     'Optional field with None default', 0.90),
    (re.compile(r'secret\s*:\s*(?:Optional\[)?str(?:\])?\s*=\s*None'),
     'Optional field with None default', 0.90),
    (re.compile(r'password\s*:\s*(?:Optional\[)?str(?:\])?\s*=\s*None'),
     'Optional field with None default', 0.90),
    (re.compile(r'token\s*:\s*(?:Optional\[)?str(?:\])?\s*=\s*None'),
     'Optional field with None default', 0.85),

    # SecretStr type (Pydantic secure string)
    (re.compile(r':\s*SecretStr\b'),
     'Pydantic SecretStr type', 0.95),

    # model_config or Config class
    (re.compile(r'model_config\s*=\s*'),
     'Pydantic model config', 0.85),
    (re.compile(r'class\s+Config\s*:'),
     'Pydantic Config class', 0.85),

    # Dataclass field with default_factory
    (re.compile(r'=\s*field\s*\(\s*default_factory'),
     'Dataclass field with factory', 0.80),
]

# Framework class patterns
FRAMEWORK_CLASS_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    # Pydantic BaseModel
    (re.compile(r'class\s+\w+\s*\(\s*BaseModel\s*\)'),
     'Pydantic BaseModel', 0.80),
    (re.compile(r'class\s+\w+\s*\(\s*BaseSettings\s*\)'),
     'Pydantic BaseSettings', 0.80),
    # LangChain bases
    (re.compile(r'class\s+\w+\s*\(\s*BaseTool\s*\)'),
     'LangChain BaseTool', 0.85),
    (re.compile(r'class\s+\w+\s*\(\s*BaseRetriever\s*\)'),
     'LangChain BaseRetriever', 0.85),
    (re.compile(r'class\s+\w+\s*\(\s*BaseCallbackHandler\s*\)'),
     'LangChain BaseCallbackHandler', 0.85),
    (re.compile(r'class\s+\w+\s*\(\s*BaseLLM\s*\)'),
     'LangChain BaseLLM', 0.85),
    (re.compile(r'class\s+\w+\s*\(\s*BaseLanguageModel\s*\)'),
     'LangChain BaseLanguageModel', 0.85),
    # CrewAI bases
    (re.compile(r'class\s+\w+\s*\(\s*Agent\s*\)'),
     'CrewAI Agent', 0.80),
    (re.compile(r'class\s+\w+\s*\(\s*Task\s*\)'),
     'CrewAI Task', 0.80),
    (re.compile(r'class\s+\w+\s*\(\s*Crew\s*\)'),
     'CrewAI Crew', 0.80),
    # AutoGen bases
    (re.compile(r'class\s+\w+\s*\(\s*AssistantAgent\s*\)'),
     'AutoGen AssistantAgent', 0.85),
    (re.compile(r'class\s+\w+\s*\(\s*UserProxyAgent\s*\)'),
     'AutoGen UserProxyAgent', 0.85),
]

# Patterns that indicate schema/type context (not actual values)
TYPE_CONTEXT_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'^\s*#.*(?:type|schema|config|model)'),
     'Type-related comment'),
    (re.compile(r'@validator\s*\('),
     'Pydantic validator decorator'),
    (re.compile(r'@field_validator\s*\('),
     'Pydantic field validator'),
    (re.compile(r'@root_validator'),
     'Pydantic root validator'),
    (re.compile(r'@model_validator'),
     'Pydantic model validator'),
    (re.compile(r'TypedDict'),
     'TypedDict definition'),
    (re.compile(r'@dataclass'),
     'Dataclass decorator'),
]


def analyze_framework_context(
    file_path: str,
    content: str,
    line: int,
    raw_line: str
) -> FrameworkContext:
    """
    Analyze if the finding is in framework internal code context.

    Args:
        file_path: Path to the file
        content: Full file content (for class detection)
        line: Line number of the finding
        raw_line: The specific line content

    Returns:
        FrameworkContext with detection results
    """
    # Normalize path
    normalized_path = file_path.replace('\\', '/')

    # Check 1: Framework internal paths
    for framework, paths in FRAMEWORK_INTERNAL_PATHS.items():
        for path_pattern in paths:
            if path_pattern in normalized_path:
                return FrameworkContext(
                    is_framework_internal=True,
                    framework_name=framework,
                    pattern_type='internal_path',
                    confidence=0.85,
                    reason=f"Framework internal path: {path_pattern}"
                )

    # Check 2: Schema field patterns (type definitions)
    for pattern, description, confidence in SCHEMA_FIELD_PATTERNS:
        if pattern.search(raw_line):
            return FrameworkContext(
                is_framework_internal=True,
                framework_name='pydantic',
                pattern_type='config_schema',
                confidence=confidence,
                reason=description
            )

    # Check 3: Framework class patterns (in surrounding content)
    # Look at a window of content around the line
    lines = content.split('\n')
    start_line = max(0, line - 20)
    end_line = min(len(lines), line + 5)
    context_window = '\n'.join(lines[start_line:end_line])

    for pattern, description, confidence in FRAMEWORK_CLASS_PATTERNS:
        if pattern.search(context_window):
            return FrameworkContext(
                is_framework_internal=True,
                framework_name='framework_class',
                pattern_type='framework_class',
                confidence=confidence,
                reason=description
            )

    # Check 4: Type context patterns
    for pattern, description in TYPE_CONTEXT_PATTERNS:
        if pattern.search(raw_line) or pattern.search(context_window):
            return FrameworkContext(
                is_framework_internal=True,
                framework_name='type_context',
                pattern_type='type_annotation',
                confidence=0.75,
                reason=description
            )

    # No framework context detected
    return FrameworkContext(
        is_framework_internal=False,
        framework_name='',
        pattern_type='',
        confidence=0.0,
        reason="Not framework internal code"
    )


def is_credential_schema_definition(raw_line: str) -> bool:
    """
    Quick check if a line is a credential schema definition.

    Used for fast filtering before full analysis.

    Args:
        raw_line: The line content to check

    Returns:
        True if the line appears to be a schema definition
    """
    # Skip comments
    stripped = raw_line.strip()
    if stripped.startswith('#') or stripped.startswith('//'):
        return False

    for pattern, _, _ in SCHEMA_FIELD_PATTERNS:
        if pattern.search(raw_line):
            return True
    return False


def is_framework_internal_path(file_path: str) -> Tuple[bool, str]:
    """
    Quick check if file path is within a known framework.

    Args:
        file_path: Path to the file

    Returns:
        Tuple of (is_internal, framework_name)
    """
    normalized_path = file_path.replace('\\', '/')

    for framework, paths in FRAMEWORK_INTERNAL_PATHS.items():
        for path_pattern in paths:
            if path_pattern in normalized_path:
                return (True, framework)

    return (False, '')


def get_framework_confidence_multiplier(framework_context: FrameworkContext) -> float:
    """
    Get the confidence multiplier based on framework context.

    Args:
        framework_context: The detected framework context

    Returns:
        Multiplier to apply to base confidence (0.0-1.0)
    """
    if not framework_context.is_framework_internal:
        return 1.0

    if framework_context.pattern_type == 'config_schema':
        return 0.05  # Strong suppression for schema definitions
    elif framework_context.pattern_type == 'internal_path':
        return 0.15  # Significant reduction for framework internals
    elif framework_context.pattern_type == 'framework_class':
        return 0.20  # Moderate reduction for framework base classes
    elif framework_context.pattern_type == 'type_annotation':
        return 0.25  # Some reduction for type-only contexts
    else:
        return 0.50  # Default reduction for unknown framework context
