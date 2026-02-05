"""
Three-stage semantic analysis engine for AGENT-004 credential detection.

Stage 1: Candidate Discovery - Pattern matching + AST assignment discovery
Stage 2: Value Analysis - Classify value type and analyze for false positives
Stage 3: Context Adjustment - File type and path-based confidence scoring

This engine dramatically reduces false positives while maintaining high recall
for known credential formats (sk-proj-, sk-ant-, co-*, etc.).
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

from agent_audit.analysis.entropy import shannon_entropy, entropy_confidence
from agent_audit.analysis.placeholder_detector import is_placeholder, is_vendor_example
from agent_audit.analysis.value_analyzer import KNOWN_CREDENTIAL_FORMATS, detect_uuid_format
from agent_audit.analysis.identifier_analyzer import (
    analyze_identifier,
    IdentifierCategory,
)
from agent_audit.analysis.framework_detector import (
    is_credential_schema_definition,
    is_framework_internal_path,
)
from agent_audit.analysis.context_classifier import (
    classify_file_context,
    FileContext,
)
from agent_audit.analysis.rule_context_config import get_context_multiplier
from agent_audit.parsers.treesitter_parser import TreeSitterParser, ValueType

logger = logging.getLogger(__name__)


class AnalysisContext(Enum):
    """Context where a potential credential was found."""
    ASSIGNMENT = "assignment"
    FUNCTION_DECLARATION = "function_declaration"
    CLASS_DEFINITION = "class_definition"
    TYPE_ANNOTATION = "type_annotation"
    IMPORT_STATEMENT = "import_statement"
    COMMENT = "comment"
    DOCUMENTATION = "documentation"
    UNKNOWN = "unknown"


@dataclass
class SemanticCandidate:
    """A candidate credential found during stage 1."""
    identifier: str
    value: str
    value_type: ValueType
    context: AnalysisContext
    line: int
    column: int
    end_column: int
    raw_text: str
    pattern_name: Optional[str] = None


@dataclass
class SemanticAnalysisResult:
    """Result of three-stage semantic analysis."""
    should_report: bool
    confidence: float
    tier: str
    reason: str
    candidate: SemanticCandidate
    format_matched: Optional[str] = None
    entropy: float = 0.0
    is_placeholder: bool = False


# File type multipliers for context adjustment (Stage 3)
FILE_TYPE_MULTIPLIERS: Dict[str, float] = {
    # Documentation files - significantly lower confidence for generic patterns
    ".md": 0.40,  # v0.5.1: Reduced from 0.85 to prevent BLOCK on docs
    ".rst": 0.40,
    ".txt": 0.40,
    ".adoc": 0.40,
    # Test files - lower confidence (test data, mocks, fixtures)
    # v0.5.1: Reduced from 0.90 to 0.55 to move generic patterns out of WARN tier
    ".test.py": 0.55,
    ".test.ts": 0.55,
    ".test.js": 0.55,
    ".spec.py": 0.55,
    ".spec.ts": 0.55,
    ".spec.js": 0.55,
    # Config files - higher (often contain real secrets)
    ".env": 1.0,
    ".env.local": 1.0,
    ".env.production": 1.0,
}

# Generic pattern names that should never reach BLOCK tier without known format
GENERIC_PATTERN_NAMES: set = {
    "Generic API Key",
    "Generic Secret/Password",
    "Generic Token",
    "Generic Secret",
    "Generic Password",
}

# Path patterns that suggest test/example code
TEST_PATH_PATTERNS: List[re.Pattern] = [
    re.compile(r"/tests?/", re.IGNORECASE),
    re.compile(r"/spec/", re.IGNORECASE),
    re.compile(r"/fixtures?/", re.IGNORECASE),
    re.compile(r"/examples?/", re.IGNORECASE),
    re.compile(r"/samples?/", re.IGNORECASE),
    re.compile(r"/mock/", re.IGNORECASE),
    re.compile(r"/demo/", re.IGNORECASE),
    re.compile(r"_test\.py$", re.IGNORECASE),
    re.compile(r"_spec\.py$", re.IGNORECASE),
    re.compile(r"\.test\.[jt]sx?$", re.IGNORECASE),
    re.compile(r"\.spec\.[jt]sx?$", re.IGNORECASE),
]

# Known high-confidence credential prefixes (KNOWN-004 fix)
# IMPORTANT: Sorted by prefix length (longest first) to ensure more specific matches take priority
HIGH_CONFIDENCE_PREFIXES: List[Tuple[str, str, float]] = [
    # Private keys (critical, should always be flagged)
    ("-----BEGIN RSA PRIVATE KEY", "RSA Private Key", 0.98),
    ("-----BEGIN DSA PRIVATE KEY", "DSA Private Key", 0.98),
    ("-----BEGIN EC PRIVATE KEY", "EC Private Key", 0.98),
    ("-----BEGIN OPENSSH PRIVATE KEY", "OpenSSH Private Key", 0.98),
    ("-----BEGIN PRIVATE KEY", "Generic Private Key", 0.98),
    ("-----BEGIN PGP PRIVATE KEY", "PGP Private Key", 0.98),
    # Anthropic (longer prefix first to avoid sk- matching)
    ("sk-ant-api", "Anthropic API Key", 0.95),
    ("sk-ant-", "Anthropic API Key", 0.93),
    # OpenAI (after Anthropic)
    ("sk-proj-", "OpenAI Project API Key", 0.95),
    # Stripe (sk_live_ and sk_test_ before generic sk-)
    ("sk_live_", "Stripe Live Secret Key", 0.95),
    ("sk_test_", "Stripe Test Secret Key", 0.85),
    # OpenAI Legacy (last among sk- prefixes)
    ("sk-", "OpenAI Legacy API Key", 0.90),
    # Cohere
    ("co-", "Cohere API Key", 0.85),
    # AWS
    ("AKIA", "AWS Access Key ID", 0.95),
    # GitHub
    ("ghp_", "GitHub Personal Access Token", 0.95),
    ("gho_", "GitHub OAuth Token", 0.95),
    ("ghs_", "GitHub App Token", 0.95),
    ("ghr_", "GitHub Refresh Token", 0.95),
    # Slack
    ("xoxb-", "Slack Bot Token", 0.95),
    ("xoxp-", "Slack User Token", 0.95),
    # Google
    ("AIza", "Google API Key", 0.95),
    # SendGrid
    ("SG.", "SendGrid API Key", 0.95),
    # Twilio (SK is common, lower confidence)
    ("SK", "Twilio API Key SID", 0.75),
    # NPM/PyPI
    ("npm_", "NPM Token", 0.95),
    ("pypi-", "PyPI API Token", 0.95),
]


class SemanticAnalyzer:
    """
    Three-stage semantic analyzer for credential detection.

    Integrates tree-sitter parsing, value analysis, and context scoring
    to provide high-precision credential detection with minimal false positives.
    """

    # Languages supported for AST analysis
    SUPPORTED_LANGUAGES = {".py", ".ts", ".tsx", ".js", ".jsx"}

    def __init__(self):
        """Initialize the semantic analyzer."""
        self._parser_cache: Dict[str, TreeSitterParser] = {}

    def analyze_file(
        self,
        content: str,
        file_path: str,
        candidates: Optional[List[Dict[str, Any]]] = None
    ) -> List[SemanticAnalysisResult]:
        """
        Perform full three-stage analysis on a file.

        Args:
            content: File content
            file_path: Path to the file
            candidates: Optional pre-discovered candidates from regex scanner

        Returns:
            List of analysis results for each candidate
        """
        results: List[SemanticAnalysisResult] = []

        # Stage 1: Candidate Discovery
        all_candidates = self._discover_candidates(content, file_path, candidates)

        # Stage 2 & 3: Analyze each candidate
        for candidate in all_candidates:
            result = self._analyze_candidate(candidate, file_path)
            results.append(result)

        return results

    def analyze_single_match(
        self,
        identifier: str,
        value: str,
        line: int,
        column: int,
        end_column: int,
        raw_line: str,
        file_path: str,
        pattern_name: str,
        content: Optional[str] = None
    ) -> SemanticAnalysisResult:
        """
        Analyze a single regex match through the three-stage pipeline.

        This is the main entry point for integrating with the existing
        SecretScanner's _is_false_positive() method.

        Args:
            identifier: Variable/key name (may be empty for raw matches)
            value: The matched value
            line: Line number
            column: Start column
            end_column: End column
            raw_line: The full line content
            file_path: Path to the file
            pattern_name: Name of the pattern that matched
            content: Full file content (optional, for AST analysis)

        Returns:
            SemanticAnalysisResult with decision and confidence
        """
        # Determine context from raw line
        context = self._determine_context_from_line(raw_line, identifier)

        # Determine value type
        value_type = self._infer_value_type(value, raw_line, content, file_path, line)

        candidate = SemanticCandidate(
            identifier=identifier,
            value=value,
            value_type=value_type,
            context=context,
            line=line,
            column=column,
            end_column=end_column,
            raw_text=raw_line,
            pattern_name=pattern_name,
        )

        return self._analyze_candidate(candidate, file_path)

    def _discover_candidates(
        self,
        content: str,
        file_path: str,
        regex_candidates: Optional[List[Dict[str, Any]]] = None
    ) -> List[SemanticCandidate]:
        """
        Stage 1: Discover credential candidates.

        Combines regex-based discovery with AST-based assignment discovery.
        """
        candidates: List[SemanticCandidate] = []

        # Path A: Convert regex candidates
        if regex_candidates:
            for rc in regex_candidates:
                candidate = SemanticCandidate(
                    identifier=rc.get("identifier", ""),
                    value=rc.get("value", ""),
                    value_type=ValueType.LITERAL_STRING,
                    context=AnalysisContext.UNKNOWN,
                    line=rc.get("line", 1),
                    column=rc.get("column", 0),
                    end_column=rc.get("end_column", 0),
                    raw_text=rc.get("raw_text", ""),
                    pattern_name=rc.get("pattern_name"),
                )
                candidates.append(candidate)

        # Path B: AST-based discovery for supported languages
        suffix = Path(file_path).suffix.lower()
        if suffix in self.SUPPORTED_LANGUAGES:
            ast_candidates = self._discover_from_ast(content, file_path)
            # Merge, avoiding duplicates on same line
            existing_lines = {c.line for c in candidates}
            for ac in ast_candidates:
                if ac.line not in existing_lines:
                    candidates.append(ac)

        return candidates

    def _discover_from_ast(
        self,
        content: str,
        file_path: str
    ) -> List[SemanticCandidate]:
        """Discover candidates using tree-sitter AST analysis."""
        candidates: List[SemanticCandidate] = []

        try:
            parser = TreeSitterParser(content, file_path=file_path)
            assignments = parser.find_assignments()

            for assign in assignments:
                # Only consider string literal assignments
                if assign.value_type != ValueType.LITERAL_STRING:
                    continue

                # Check if the value looks like it could be a credential
                value = self._extract_string_content(assign.value)
                if not self._could_be_credential(assign.name, value):
                    continue

                candidate = SemanticCandidate(
                    identifier=assign.name,
                    value=value,
                    value_type=assign.value_type,
                    context=AnalysisContext.ASSIGNMENT,
                    line=assign.line,
                    column=assign.column,
                    end_column=assign.end_column,
                    raw_text=assign.raw_text,
                )
                candidates.append(candidate)

        except Exception as e:
            logger.debug(f"AST parsing failed for {file_path}: {e}")

        return candidates

    def _analyze_candidate(
        self,
        candidate: SemanticCandidate,
        file_path: str
    ) -> SemanticAnalysisResult:
        """
        Stage 2 & 3: Analyze a candidate and compute final confidence.
        """
        # Stage 2: Value Analysis
        should_report, base_confidence, reason = self._stage2_value_analysis(candidate)

        if not should_report:
            return SemanticAnalysisResult(
                should_report=False,
                confidence=base_confidence,
                tier=self._confidence_to_tier(base_confidence),
                reason=reason,
                candidate=candidate,
                entropy=shannon_entropy(candidate.value) if candidate.value else 0.0,
            )

        # Check for known format match FIRST
        format_matched, format_confidence = self._match_known_format(candidate.value)
        if format_matched:
            base_confidence = max(base_confidence, format_confidence)

        # Calculate entropy
        entropy = shannon_entropy(candidate.value) if candidate.value else 0.0

        # Check placeholder - BUT skip if value contains known credential patterns
        # This prevents connection strings with example.com from being rejected
        should_check_placeholder = True
        if candidate.value:
            # Skip placeholder check for connection strings with credentials
            if re.search(r'://[^:]+:[^@]+@', candidate.value):
                should_check_placeholder = False
            # Skip if matches a known credential format
            if format_matched:
                should_check_placeholder = False

        # v0.5.1: Always check placeholders for path patterns, even for "matched" formats
        # The "Potential AWS Secret Key" pattern matches too broadly (any 40-char base64)
        # and can hit file paths in shell scripts. Path detection should take priority.
        placeholder_result = is_placeholder(candidate.value) if candidate.value else None
        is_placeholder_val = placeholder_result.is_placeholder if placeholder_result else False
        is_path_pattern = placeholder_result and "path" in (placeholder_result.reason or "").lower()

        if should_check_placeholder or is_path_pattern:
            if is_placeholder_val and (placeholder_result.confidence if placeholder_result else 0) >= 0.85:
                return SemanticAnalysisResult(
                    should_report=False,
                    confidence=0.1,
                    tier="SUPPRESSED",
                    reason=f"Placeholder detected: {placeholder_result.reason if placeholder_result else 'unknown'}",
                    candidate=candidate,
                    entropy=entropy,
                    is_placeholder=True,
                )

        # Stage 3: Context Adjustment
        # Note: SemanticAnalyzer is primarily used for AGENT-004 (hardcoded credentials)
        adjusted_confidence = self._stage3_context_adjustment(
            base_confidence, file_path, candidate, rule_id="AGENT-004"
        )

        # v0.5.1: Cap generic patterns that don't match known formats
        # Generic patterns should never reach BLOCK tier without a known format match
        pattern_name = candidate.pattern_name or ""
        is_generic_pattern = pattern_name in GENERIC_PATTERN_NAMES or any(
            g.lower() in pattern_name.lower() for g in ("generic", "secret/password")
        )
        if is_generic_pattern and not format_matched:
            # Cap confidence at 0.70 (WARN tier) for generic patterns
            # This prevents "Found Generic Secret/Password" from being BLOCK
            max_generic_confidence = 0.70
            if adjusted_confidence > max_generic_confidence:
                adjusted_confidence = max_generic_confidence
                reason = f"{reason} (capped: generic pattern without known format)"

        # Final determination
        tier = self._confidence_to_tier(adjusted_confidence)
        should_report_final = adjusted_confidence >= 0.30 and tier != "SUPPRESSED"

        return SemanticAnalysisResult(
            should_report=should_report_final,
            confidence=adjusted_confidence,
            tier=tier,
            reason=reason,
            candidate=candidate,
            format_matched=format_matched,
            entropy=entropy,
            is_placeholder=False,
        )

    def _stage2_value_analysis(
        self,
        candidate: SemanticCandidate
    ) -> Tuple[bool, float, str]:
        """
        Stage 2: Analyze the value to determine if it's a real credential.

        Returns:
            Tuple of (should_continue, confidence, reason)
        """
        value = candidate.value
        value_type = candidate.value_type
        context = candidate.context
        identifier = candidate.identifier

        # === NEW: UUID Format Detection ===
        # Check if value is UUID format BEFORE other analysis
        uuid_analysis = detect_uuid_format(value)
        if uuid_analysis.is_uuid:
            # UUID detected - check identifier context
            id_analysis = analyze_identifier(identifier)

            if id_analysis.category == IdentifierCategory.DATA_IDENTIFIER:
                # Strong signal: UUID + data identifier variable name
                # This is almost certainly NOT a credential
                return (
                    False,
                    0.05,
                    f"UUID format ({uuid_analysis.format_name}) with data identifier "
                    f"variable '{identifier}' ({id_analysis.reason})"
                )

            if id_analysis.category == IdentifierCategory.CREDENTIAL:
                # UUID with credential variable name - unusual but possible
                # Reduce confidence but don't suppress
                return (
                    True,
                    0.5 * id_analysis.confidence_multiplier,
                    f"UUID format with credential variable '{identifier}' - verify manually"
                )

            if id_analysis.category == IdentifierCategory.AMBIGUOUS:
                # Ambiguous identifier with UUID - likely data token
                # Apply moderate reduction
                if identifier.lower() in ('token', 'tok', 't'):
                    # Bare 'token' variable with UUID is almost always data
                    return (
                        True,
                        0.15,
                        f"UUID format with ambiguous variable '{identifier}' - likely data token"
                    )
                return (
                    True,
                    0.25,
                    f"UUID format ({uuid_analysis.format_name}) - context unclear"
                )

        # === NEW: Identifier Context Analysis (for non-UUID values) ===
        if identifier:
            id_analysis = analyze_identifier(identifier)
            if id_analysis.category == IdentifierCategory.DATA_IDENTIFIER:
                # Variable name strongly suggests data identifier, not credential
                # Apply confidence multiplier
                base_multiplier = id_analysis.confidence_multiplier
                # If value also doesn't match known credential formats, suppress
                if not self._match_known_format(value)[0]:
                    return (
                        True,
                        0.2 * base_multiplier,
                        f"Data identifier variable '{identifier}' ({id_analysis.reason})"
                    )

        # === NEW: Framework Schema Detection (AGENT-004 FP Reduction) ===
        # Check if this is a Pydantic/dataclass schema definition
        if is_credential_schema_definition(candidate.raw_text):
            return (
                False,
                0.05,
                "Schema field definition (Pydantic/dataclass) - not a hardcoded credential"
            )

        # === NEW v0.8.0: F-String ENV Interpolation Detection ===
        # Check if value appears to be an f-string with env-sourced variables
        # This reduces confidence for patterns like: f"postgres://{DB_USER}:{DB_PASS}@..."
        raw_text = candidate.raw_text
        if raw_text and ('{' in raw_text or '${' in raw_text):
            # Check if this looks like Python f-string or JS template literal
            if "f'" in raw_text or 'f"' in raw_text or '`' in raw_text:
                # We need file content to trace env vars - check if available
                # For now, use a heuristic: common env variable naming patterns
                env_var_pattern = r'\{([A-Z][A-Z0-9_]*)\}'
                import re as regex_module
                env_matches = regex_module.findall(env_var_pattern, raw_text)
                if env_matches:
                    # Variable names look like environment variables (ALL_CAPS)
                    # This is a strong signal that values come from env, not hardcoded
                    return (
                        True,
                        0.15,
                        f"F-string with env-style variables: {', '.join(env_matches[:3])}"
                    )

        # === Immediate Exclusions (confidence = 0.0) ===

        # Exclude function calls
        if value_type == ValueType.FUNCTION_CALL:
            return (False, 0.0, "Value is function call")

        # Exclude variable references
        if value_type == ValueType.VARIABLE_REF:
            return (False, 0.0, "Value is variable reference")

        # Exclude environment variable reads
        if value_type == ValueType.ENV_READ:
            return (False, 0.0, "Value is environment variable read")

        # Exclude type definitions
        if value_type == ValueType.TYPE_DEFINITION:
            return (False, 0.0, "Value is type/schema definition")

        # Exclude None/null values
        if value_type == ValueType.NONE_NULL:
            return (False, 0.0, "Value is null/None/undefined")

        # Exclude function declarations
        if context == AnalysisContext.FUNCTION_DECLARATION:
            return (False, 0.0, "Identifier is function name")

        # Exclude class definitions
        if context == AnalysisContext.CLASS_DEFINITION:
            return (False, 0.0, "Identifier is class name")

        # Exclude import statements
        if context == AnalysisContext.IMPORT_STATEMENT:
            return (False, 0.0, "Found in import statement")

        # Exclude type annotations
        if context == AnalysisContext.TYPE_ANNOTATION:
            return (False, 0.0, "Found in type annotation")

        # === Value-based checks ===

        # Empty or very short values
        if not value or len(value) < 8:
            return (False, 0.1, f"Value too short ({len(value) if value else 0} chars)")

        # Value equals identifier name (e.g., api_key = "api_key")
        if value and identifier and value.lower() == identifier.lower():
            return (False, 0.05, "Value equals variable name (likely placeholder)")

        # All same character
        if value and len(set(value)) == 1:
            return (False, 0.05, "Single repeated character")

        # Check if value looks like a class name (PascalCase with multiple caps)
        if self._looks_like_class_name(value):
            return (False, 0.1, "Value looks like class/type name")

        # === NEW v0.8.0: Vendor Example Key Detection ===
        # Check for known vendor example keys (e.g., AKIAIOSFODNN7EXAMPLE)
        # This must happen BEFORE known format matching to avoid false positives
        is_example, example_conf, example_reason = is_vendor_example(value)
        if is_example and example_conf >= 0.85:
            return (
                False,
                0.02,
                f"Vendor example key detected: {example_reason}"
            )

        # Check for known credential prefixes FIRST (before other patterns)
        # This ensures ghp_, sk-proj-, etc. are not rejected by other patterns
        for prefix, name, conf in HIGH_CONFIDENCE_PREFIXES:
                # Private key headers are complete patterns, no random part needed
                if prefix.startswith("-----BEGIN"):
                    return (True, conf, f"Known format: {name}")
                # For API keys, require additional random part
                random_part = value[len(prefix):]
                if len(random_part) >= 10:
                    return (True, conf, f"Known format: {name}")

        # Check for common non-credential patterns (AFTER known format check)
        non_cred_patterns = [
            (r"^[A-Z_]+$", "All caps constant name"),
            (r"^https?://", "URL (not credential)"),
            (r"^[a-z_][a-z0-9_]*$", "Lowercase identifier"),
        ]
        for pattern, reason in non_cred_patterns:
            if re.match(pattern, value):
                return (False, 0.15, reason)

        # Entropy analysis for unknown formats
        entropy = shannon_entropy(value)
        entropy_conf = entropy_confidence(value)

        if entropy < 2.5:
            return (False, 0.2, f"Low entropy ({entropy:.2f})")

        # High entropy unknown format
        return (True, entropy_conf, f"High entropy ({entropy:.2f})")

    def _stage3_context_adjustment(
        self,
        base_confidence: float,
        file_path: str,
        candidate: SemanticCandidate,
        rule_id: str = "AGENT-004"
    ) -> float:
        """
        Stage 3: Adjust confidence based on file/path context.

        v0.8.0: Uses ContextClassifier for file classification and
        per-rule context multipliers for aggressive FP suppression.
        """
        adjusted = base_confidence

        # Check if this is a critical pattern that shouldn't be heavily penalized
        # Private keys and connection strings are always serious, even in docs/txt files
        is_critical_pattern = False
        value = candidate.value or ""
        if value.startswith("-----BEGIN") and "PRIVATE KEY" in value:
            is_critical_pattern = True
        elif "://" in value and "@" in value:  # Connection string with credentials
            is_critical_pattern = True

        # === v0.8.0: Context Classification ===
        # Use the new ContextClassifier for deterministic file classification
        file_context = classify_file_context(file_path)

        # Apply per-rule context multiplier
        # This is the core v0.8.0 improvement for FP reduction
        if not is_critical_pattern:
            context_multiplier = get_context_multiplier(rule_id, file_context)
            if context_multiplier < 1.0:
                adjusted *= context_multiplier
                logger.debug(
                    f"Context adjustment: {file_path} ({file_context.value}) "
                    f"× {context_multiplier} for {rule_id}"
                )

        # === Framework Internal Path Detection (AGENT-004 FP Reduction) ===
        # Check if file is in a known framework's internal code
        is_internal, framework = is_framework_internal_path(file_path)
        if is_internal and not is_critical_pattern:
            # Significantly reduce confidence for findings in framework internals
            # These are typically schema definitions, type hints, or config patterns
            adjusted *= 0.15  # Strong reduction for framework internal paths
            logger.debug(f"Framework internal path ({framework}): {file_path}")

        # File extension multiplier (kept for backward compatibility with specific extensions)
        # v0.8.0: Skip for file types already handled by ContextClassifier to avoid
        # double-penalizing (e.g., .md files already get DOCUMENTATION context multiplier)
        suffix = Path(file_path).suffix.lower()

        # Suffixes already handled by ContextClassifier - skip to avoid double penalty
        CONTEXT_HANDLED_SUFFIXES = {".md", ".rst", ".txt", ".adoc"}

        # Check for compound suffixes like .test.py
        filename = Path(file_path).name.lower()
        multiplier_applied = 1.0

        # Only apply FILE_TYPE_MULTIPLIERS if not already handled by context
        if suffix not in CONTEXT_HANDLED_SUFFIXES:
            for compound_suffix, multiplier in FILE_TYPE_MULTIPLIERS.items():
                if filename.endswith(compound_suffix):
                    multiplier_applied = multiplier
                    break
            else:
                # Check simple suffix
                if suffix in FILE_TYPE_MULTIPLIERS:
                    multiplier_applied = FILE_TYPE_MULTIPLIERS[suffix]

        # For critical patterns, use minimum floor of 0.85 on multiplier
        if is_critical_pattern and multiplier_applied < 0.85:
            multiplier_applied = 0.85

        adjusted *= multiplier_applied

        # v0.8.0: Skip legacy TEST_PATH_PATTERNS if ContextClassifier already applied
        # This avoids double-penalizing test files
        if file_context == FileContext.PRODUCTION:
            # Only apply legacy path patterns if ContextClassifier didn't catch it
            path_str = file_path.replace("\\", "/")
            for pattern in TEST_PATH_PATTERNS:
                if pattern.search(path_str):
                    # v0.5.1: Lower multiplier for test paths (0.55)
                    path_multiplier = 0.55
                    if is_critical_pattern:
                        path_multiplier = max(path_multiplier, 0.85)
                    adjusted *= path_multiplier
                    break

        # Documentation context in line
        raw_lower = candidate.raw_text.lower()
        if "# example" in raw_lower or "// example" in raw_lower:
            adjusted *= 0.7
        if "# todo" in raw_lower or "// todo" in raw_lower:
            adjusted *= 0.6

        return min(1.0, max(0.0, adjusted))

    def _determine_context_from_line(
        self,
        raw_line: str,
        identifier: str
    ) -> AnalysisContext:
        """Determine the analysis context from a raw line."""
        stripped = raw_line.strip()

        if stripped.startswith("def "):
            return AnalysisContext.FUNCTION_DECLARATION
        if stripped.startswith("class "):
            return AnalysisContext.CLASS_DEFINITION
        if stripped.startswith("import ") or stripped.startswith("from "):
            return AnalysisContext.IMPORT_STATEMENT
        if stripped.startswith("#") or stripped.startswith("//"):
            return AnalysisContext.COMMENT
        if '"""' in stripped or "'''" in stripped:
            return AnalysisContext.DOCUMENTATION

        # Check for type annotations
        type_patterns = [
            r":\s*(Optional\[)?SecretStr",
            r":\s*(str|int|float|bool|List|Dict|Any)",
            r"->\s*\w+:",
        ]
        for pattern in type_patterns:
            if re.search(pattern, raw_line):
                return AnalysisContext.TYPE_ANNOTATION

        # Check for assignment
        if "=" in raw_line and identifier:
            return AnalysisContext.ASSIGNMENT

        return AnalysisContext.UNKNOWN

    def _infer_value_type(
        self,
        value: str,
        raw_line: str,
        content: Optional[str],
        file_path: str,
        line_num: int
    ) -> ValueType:
        """Infer the value type from context."""
        suffix = Path(file_path).suffix.lower()
        is_typescript = suffix in (".ts", ".tsx")
        is_javascript = suffix in (".js", ".jsx")

        # v0.5.1: Clean up value - remove trailing punctuation that may be captured by regex
        clean_value = value.rstrip(",;}")

        # Check for env reads
        env_patterns = [
            r"os\.environ\.get\s*\(",
            r"os\.environ\[",
            r"os\.getenv\s*\(",
            r"getenv\s*\(",
            r"process\.env\.",
            r"settings\.\w+",
            r"config\.\w+",
            r"Config\.\w+",
            r"get_from_\w+\s*\(",
        ]
        for pattern in env_patterns:
            if re.search(pattern, raw_line):
                return ValueType.ENV_READ

        # === TypeScript/JavaScript specific patterns ===
        if is_typescript or is_javascript:
            # v0.5.1: Template literal with variable interpolation
            # Pattern: `password=${this.code}` or `secret=${variable}`
            # The value is from a variable, not hardcoded
            if re.search(r'`[^`]*\$\{', raw_line):
                # Template literal with interpolation - value comes from variable
                return ValueType.VARIABLE_REF

            # v0.5.1: Ternary expression as object property value
            # Pattern: "password: condition ? value1 : value2"
            # Even if value1 is a variable, this is dynamic assignment
            if re.search(r":\s*[^,]+\s*\?\s*[^:]+\s*:\s*[^,]+\s*[,}]", raw_line):
                return ValueType.VARIABLE_REF

            # v0.5.1: Nullish coalescing or logical OR as value
            # Pattern: "password ?? defaultValue" or "secret || fallback"
            if re.search(r"=\s*[^=]+\s*(\?\?|\|\|)\s*", raw_line):
                return ValueType.VARIABLE_REF

            # TypeScript interface property signature: "webhookSecret?: string" or "password: string"
            if re.search(r"^\s*\w+\??\s*:\s*(string|number|boolean|any|unknown|never|void|null|undefined|bigint|symbol)\b", raw_line):
                return ValueType.TYPE_DEFINITION

            # Zod schema definition: "password: z.string().optional()" or "z.string()" chains
            if re.search(r"\bz\.(string|number|boolean|object|array|enum|literal|union|optional|nullable)", raw_line):
                return ValueType.TYPE_DEFINITION

            # Member expression / property access: "state.password", "form.apiKey", "config.secret"
            # Pattern: identifier = someObject.property (the value is a property access, not hardcoded)
            if re.search(r"=\s*[a-zA-Z_]\w*\.[a-zA-Z_]\w*\s*[,;}\)]?\s*$", raw_line):
                return ValueType.VARIABLE_REF

            # v0.5.1: Optional chaining property access (assignment): "= params.cfg?.auth?.password"
            # Also matches deep property access: "= obj.prop1.prop2.prop3"
            if re.search(r"=\s*[a-zA-Z_]\w*(\??\.[a-zA-Z_]\w*)+\s*[;,})\]]?\s*$", raw_line):
                return ValueType.VARIABLE_REF

            # v0.5.1: Optional chaining property access (object literal): "key: opts.auth?.password"
            # Pattern: identifier?.property or identifier.property?.subproperty
            if re.search(r":\s*[a-zA-Z_]\w*(\??\.[a-zA-Z_]\w*)+\s*[,;})\]]", raw_line):
                return ValueType.VARIABLE_REF

            # Object spread/destructuring: "password: state.password" or "{ password }"
            if re.search(r":\s*[a-zA-Z_]\w*\.[a-zA-Z_]\w*\s*[,}]", raw_line):
                return ValueType.VARIABLE_REF

            # v0.5.1: Object property with member expression including method call
            # Pattern: "password: this.opts.password" or "secret: state.secret.trim()"
            if re.search(r":\s*(?:this|self)\.\w+\.\w+", raw_line):
                return ValueType.VARIABLE_REF

            # v0.5.1: Object property with simple member expression
            # Pattern: "password: host.password" or "token: config.token"
            if re.search(r":\s*[a-zA-Z_]\w*\.\w+\s*[,;})\]]", raw_line):
                return ValueType.VARIABLE_REF

            # v0.5.1: Object property shorthand or simple variable reference
            # Pattern: "password: someVariable," or "secret: _secret,"
            # The value is a bare identifier (variable name), not a string literal
            if clean_value and re.match(r"^[a-zA-Z_]\w*$", clean_value):
                # Check if it's an object property with a variable value (not a string literal)
                # Look for pattern: "key: identifier," or "key: identifier}"
                prop_pattern = rf":\s*{re.escape(clean_value)}\s*[,}}\])]"
                if re.search(prop_pattern, raw_line):
                    # Verify it's not inside quotes
                    if not re.search(rf'["\'][^"\']*{re.escape(clean_value)}[^"\']*["\']', raw_line):
                        return ValueType.VARIABLE_REF

            # Shorthand property in object: "{ password, apiKey }" - just an identifier reference
            if re.search(r"\{\s*(\w+\s*,\s*)*" + re.escape(clean_value) + r"\s*(,|\})", raw_line):
                return ValueType.VARIABLE_REF

            # v0.5.1: Destructuring assignment with renaming: "const { password: pwd } = obj"
            # The colon here is for renaming, not value assignment
            if re.search(r"const\s*\{.*" + re.escape(clean_value) + r".*\}\s*=", raw_line):
                return ValueType.VARIABLE_REF
            if re.search(r"let\s*\{.*" + re.escape(clean_value) + r".*\}\s*=", raw_line):
                return ValueType.VARIABLE_REF

            # TypeScript type alias: "type ApiKey = string"
            if re.search(r"^\s*type\s+\w+\s*=", raw_line):
                return ValueType.TYPE_DEFINITION

            # TypeScript interface declaration line
            if re.search(r"^\s*interface\s+\w+", raw_line):
                return ValueType.TYPE_DEFINITION

            # TypeScript/JS function parameter with type: "(password: string)"
            if re.search(r"\(\s*\w+\s*:\s*(string|number|boolean|any)", raw_line):
                return ValueType.TYPE_DEFINITION

            # Generic type parameter: "<T extends Secret>"
            if re.search(r"<\s*\w+\s+extends\s+\w+", raw_line):
                return ValueType.TYPE_DEFINITION

            # Arrow function or method with return type: "(): string =>" or "(): Promise<string>"
            if re.search(r"\)\s*:\s*\w+(\s*<[^>]+>)?\s*(=>|{)", raw_line):
                # The matched pattern is likely a return type, not a credential
                return ValueType.TYPE_DEFINITION

        # Check for function calls
        if re.search(r"[a-zA-Z_]\w*\s*\(", value):
            return ValueType.FUNCTION_CALL

        # v0.5.1: Check if the value itself looks like a property access
        # Pattern: identifier.property or identifier.property.subproperty
        # This catches cases like "opts.password" or "authPassword.length"
        if re.match(r"^[a-zA-Z_]\w*(\??\.[a-zA-Z_]\w*)+$", clean_value):
            return ValueType.VARIABLE_REF

        # Check for variable references (identifier without quotes)
        # v0.5.1: Use clean_value for identifier check
        if re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", clean_value):
            # Could be variable ref if not in quotes in the line
            # Check if the value appears inside a quoted string in the line
            # by looking for quote patterns around the value
            in_quotes = False
            # Check for double-quoted context
            if re.search(rf'"[^"]*{re.escape(clean_value)}[^"]*"', raw_line):
                in_quotes = True
            # Check for single-quoted context
            elif re.search(rf"'[^']*{re.escape(clean_value)}[^']*'", raw_line):
                in_quotes = True
            if not in_quotes:
                return ValueType.VARIABLE_REF

        # Check for None/null
        if clean_value.lower() in ("none", "null", "undefined", "nil"):
            return ValueType.NONE_NULL

        # Use tree-sitter for supported languages if content available
        if content:
            if suffix in self.SUPPORTED_LANGUAGES:
                try:
                    parser = TreeSitterParser(content, file_path=file_path)
                    assignments = parser.find_assignments()
                    for assign in assignments:
                        if assign.line == line_num:
                            return assign.value_type
                except Exception:
                    pass

        # Default to literal string
        return ValueType.LITERAL_STRING

    def _match_known_format(self, value: str) -> Tuple[Optional[str], float]:
        """Match value against known credential formats."""
        if not value:
            return (None, 0.0)

        for prefix, name, conf in HIGH_CONFIDENCE_PREFIXES:
            if value.startswith(prefix):
                return (name, conf)

        # Also check the KNOWN_CREDENTIAL_FORMATS from value_analyzer
        for fmt in KNOWN_CREDENTIAL_FORMATS:
            if re.match(fmt.pattern, value):
                return (fmt.name, 0.5 + fmt.confidence_boost)

        return (None, 0.0)

    def _extract_string_content(self, value: str) -> str:
        """Extract string content from a quoted value."""
        value = value.strip()

        # Handle triple quotes
        for quote in ['"""', "'''"]:
            if value.startswith(quote) and value.endswith(quote):
                return value[3:-3]

        # Handle f-strings
        for prefix in ["f", "r", "b", "fr", "rf"]:
            for quote in ['"', "'"]:
                full_prefix = prefix + quote
                if value.lower().startswith(full_prefix) and value.endswith(quote):
                    return value[len(full_prefix):-1]

        # Handle single/double quotes
        for quote in ['"', "'"]:
            if value.startswith(quote) and value.endswith(quote):
                return value[1:-1]

        return value

    def _could_be_credential(self, identifier: str, value: str) -> bool:
        """Quick check if an identifier/value pair could be a credential."""
        if not value or len(value) < 8:
            return False

        # NEW: Check if identifier suggests data identifier
        if identifier:
            id_analysis = analyze_identifier(identifier)
            if id_analysis.category == IdentifierCategory.DATA_IDENTIFIER:
                # If identifier suggests data and value is UUID format, skip
                uuid_analysis = detect_uuid_format(value)
                if uuid_analysis.is_uuid:
                    return False

        # Check identifier name for credential hints
        cred_hints = [
            "key", "token", "secret", "password", "passwd", "pwd",
            "credential", "auth", "api", "access", "private",
        ]
        id_lower = identifier.lower()

        # NEW: But exclude if it's a data identifier pattern
        id_analysis = analyze_identifier(identifier)
        if id_analysis.category == IdentifierCategory.DATA_IDENTIFIER:
            return False

        if any(hint in id_lower for hint in cred_hints):
            return True

        # Check for known prefixes in value
        for prefix, _, _ in HIGH_CONFIDENCE_PREFIXES:
            if value.startswith(prefix):
                return True

        # Check entropy
        entropy = shannon_entropy(value)
        return entropy >= 3.0

    def _looks_like_class_name(self, value: str) -> bool:
        """Check if a value looks like a class/type name."""
        if not value:
            return False

        # PascalCase with multiple capitals
        if re.match(r"^[A-Z][a-zA-Z]+$", value):
            capital_count = sum(1 for c in value if c.isupper())
            if capital_count >= 2:
                return True

            # Common class suffixes
            class_suffixes = [
                "Memory", "Buffer", "Parser", "Handler", "Manager",
                "Factory", "Builder", "Wrapper", "Provider", "Service",
                "Client", "Server", "Controller", "Processor", "Validator",
                "Token", "Key", "Secret", "Credential",
            ]
            if any(value.endswith(suffix) for suffix in class_suffixes):
                return True

        return False

    def _confidence_to_tier(self, confidence: float) -> str:
        """Convert confidence to tier."""
        if confidence >= 0.90:
            return "BLOCK"
        elif confidence >= 0.60:
            return "WARN"
        elif confidence >= 0.30:
            return "INFO"
        else:
            return "SUPPRESSED"


# Module-level singleton for convenience
_analyzer: Optional[SemanticAnalyzer] = None


def get_analyzer() -> SemanticAnalyzer:
    """Get or create the semantic analyzer singleton."""
    global _analyzer
    if _analyzer is None:
        _analyzer = SemanticAnalyzer()
    return _analyzer


def analyze_credential_candidate(
    identifier: str,
    value: str,
    line: int,
    column: int,
    end_column: int,
    raw_line: str,
    file_path: str,
    pattern_name: str,
    content: Optional[str] = None
) -> SemanticAnalysisResult:
    """
    Convenience function to analyze a single credential candidate.

    This is the main API for the secret scanner integration.
    """
    analyzer = get_analyzer()
    return analyzer.analyze_single_match(
        identifier=identifier,
        value=value,
        line=line,
        column=column,
        end_column=end_column,
        raw_line=raw_line,
        file_path=file_path,
        pattern_name=pattern_name,
        content=content,
    )
