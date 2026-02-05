"""Rule engine for pattern matching and finding generation."""

import re
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from agent_audit.models.finding import Finding, Remediation, confidence_to_tier
from agent_audit.models.risk import Severity, Category, Location
from agent_audit.rules.loader import RuleLoader
from agent_audit.analysis.context_classifier import (
    classify_file_context,
    FileContext,
    detect_infrastructure_context,
)
from agent_audit.analysis.rule_context_config import get_context_multiplier

logger = logging.getLogger(__name__)


@dataclass
class MatchContext:
    """Context for rule matching."""
    file_path: str
    source_code: Optional[str] = None
    dangerous_patterns: List[Dict[str, Any]] = field(default_factory=list)
    tools: List[Any] = field(default_factory=list)
    mcp_servers: List[Dict[str, Any]] = field(default_factory=list)
    function_calls: List[Dict[str, Any]] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)


class RuleEngine:
    """
    Rule engine for matching patterns and generating findings.

    Loads rules from YAML files and applies them to scan results.
    """

    # Pattern type to Rule ID mapping for OWASP Agentic Top 10
    PATTERN_TYPE_TO_RULE_MAP: Dict[str, str] = {
        # ASI-01: Goal Hijack
        'prompt_injection_fstring': 'AGENT-010',
        'prompt_injection_fstring_kwarg': 'AGENT-010',
        'prompt_injection_format': 'AGENT-010',
        'system_prompt_fstring': 'AGENT-010',
        'system_prompt_concat': 'AGENT-010',
        'system_prompt_format': 'AGENT-010',
        'agent_without_input_guard': 'AGENT-011',

        # ASI-01: Goal Hijack (v0.3.0 - LangChain)
        'langchain_agent_executor_risk': 'AGENT-040',  # v0.3.1: Separate from AGENT-025 (monitoring)
        'langchain_system_prompt_injectable': 'AGENT-027',

        # ASI-02: Tool Misuse (v0.3.0 - MCP Config + LangChain)
        'mcp_overly_broad_filesystem': 'AGENT-029',
        'mcp_stdio_no_sandbox': 'AGENT-032',
        'langchain_tool_input_unsanitized': 'AGENT-026',

        # ASI-02: SQL Injection (v0.3.2)
        'sql_fstring_injection': 'AGENT-041',
        'sql_format_injection': 'AGENT-041',
        'sql_concat_injection': 'AGENT-041',
        'sql_percent_injection': 'AGENT-041',

        # ASI-08: Cascading Failures (v0.3.0 - cross-framework)
        'agent_max_iterations_unbounded': 'AGENT-028',

        # ASI-03: Identity & Privilege Abuse
        'hardcoded_credential_in_agent': 'AGENT-013',
        'excessive_tools': 'AGENT-014',
        'auto_approval': 'AGENT-014',
        'mcp_excessive_servers': 'AGENT-042',  # v0.3.2: Excessive MCP servers

        # ASI-04: Supply Chain
        'npx_unfixed_version': 'AGENT-015',
        'unofficial_mcp_source': 'AGENT-015',
        'unvalidated_rag_ingestion': 'AGENT-016',
        'mcp_unverified_server_source': 'AGENT-030',

        # ASI-05: RCE / Sensitive Exposure
        'unsandboxed_code_exec_in_tool': 'AGENT-017',
        'mcp_sensitive_env_exposure': 'AGENT-031',

        # ASI-06: Memory Poisoning
        'unsanitized_memory_write': 'AGENT-018',
        'unbounded_memory': 'AGENT-019',

        # ASI-07: Insecure Communication
        'multi_agent_no_auth': 'AGENT-020',
        'agent_comm_no_tls': 'AGENT-020',

        # ASI-08: Cascading Failures
        'missing_circuit_breaker': 'AGENT-021',
        'tool_without_error_handling': 'AGENT-022',

        # ASI-09: Trust Exploitation
        'opaque_agent_output': 'AGENT-023',
        'mcp_missing_auth': 'AGENT-033',
        'missing_human_in_loop': 'AGENT-037',
        'agent_impersonation_risk': 'AGENT-038',
        'trust_boundary_violation': 'AGENT-039',

        # ASI-10: Rogue Agents
        'no_kill_switch': 'AGENT-024',
        'no_observability': 'AGENT-025',

        # v0.3.0: ASI-02 Tool Misuse (expanded)
        'tool_no_input_validation': 'AGENT-034',
        'tool_unrestricted_execution': 'AGENT-035',
        'tool_output_trusted_blindly': 'AGENT-036',

        # v0.5.0: Expanded detection (all contexts)
        'eval_exec_expanded': 'AGENT-034',       # Eval/exec outside @tool
        'ssrf_expanded': 'AGENT-026',            # SSRF outside @tool
        'subprocess_expanded': 'AGENT-034',      # Subprocess outside @tool
        'network_request_hardcoded_url': 'AGENT-026',  # Hardcoded URL (low confidence)

        # v0.9.0: Supply chain security
        'unsafe_deserialization': 'AGENT-049',   # Pickle/torch/joblib load
    }

    # v0.3.0: MCP finding type to rule metadata
    MCP_FINDING_RULES: Dict[str, Dict[str, Any]] = {
        'mcp_overly_broad_filesystem': {
            'id': 'AGENT-029',
            'title': 'Overly Broad MCP Filesystem Access',
            'category': 'tool_misuse',
            'cwe_id': 'CWE-732',
        },
        'mcp_unverified_server_source': {
            'id': 'AGENT-030',
            'title': 'Unverified MCP Server Source',
            'category': 'supply_chain_agentic',
            'cwe_id': 'CWE-494',
        },
        'mcp_sensitive_env_exposure': {
            'id': 'AGENT-031',
            'title': 'Sensitive Environment Variable Exposure',
            'category': 'credential_exposure',
            'cwe_id': 'CWE-798',
        },
        'mcp_stdio_no_sandbox': {
            'id': 'AGENT-032',
            'title': 'MCP Server Without Sandbox Isolation',
            'category': 'tool_misuse',
            'cwe_id': 'CWE-250',
        },
        'mcp_missing_auth': {
            'id': 'AGENT-033',
            'title': 'MCP Server Without Authentication',
            'category': 'trust_exploitation',
            'cwe_id': 'CWE-306',
        },
    }

    # Pre-compiled regex patterns for common detections
    CREDENTIAL_PATTERNS = [
        (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS Access Key"),
        (re.compile(r'sk-[a-zA-Z0-9]{48}'), "OpenAI API Key"),
        (re.compile(r'sk-ant-[a-zA-Z0-9]{40,}'), "Anthropic API Key"),
        (re.compile(r'ghp_[a-zA-Z0-9]{36}'), "GitHub Personal Access Token"),
        (re.compile(r'gho_[a-zA-Z0-9]{36}'), "GitHub OAuth Token"),
        (re.compile(r'(?i)(api[_-]?key|secret|password|token)\s*[=:]\s*["\']?[a-zA-Z0-9]{20,}'),
         "Generic API Key/Secret"),
    ]

    def __init__(self, rules_dirs: Optional[List[Path]] = None):
        """
        Initialize the rule engine.

        Args:
            rules_dirs: List of directories containing rule files
        """
        self.loader = RuleLoader(rules_dirs)
        self._rules: Dict[str, Dict[str, Any]] = {}

    def load_rules(self, additional_dirs: Optional[List[Path]] = None):
        """Load rules from all configured directories."""
        if additional_dirs:
            for d in additional_dirs:
                self.loader.add_rules_directory(d)

        self._rules = self.loader.load_all_rules()
        logger.info(f"Loaded {len(self._rules)} rules")

    def add_builtin_rules_dir(self, builtin_dir: Path):
        """Add the builtin rules directory."""
        self.loader.add_rules_directory(builtin_dir)

    def evaluate(self, context: MatchContext) -> List[Finding]:
        """
        Evaluate all rules against a match context.

        Args:
            context: The context containing scan results to check

        Returns:
            List of findings from matched rules
        """
        findings: List[Finding] = []

        for rule_id, rule in self._rules.items():
            rule_findings = self._evaluate_rule(rule, context)
            findings.extend(rule_findings)

        return findings

    def evaluate_dangerous_patterns(
        self,
        patterns: List[Dict[str, Any]],
        file_path: str,
        source_code: Optional[str] = None
    ) -> List[Finding]:
        """
        Evaluate dangerous patterns detected by scanners.

        Args:
            patterns: List of dangerous patterns from scanner
            file_path: Source file path
            source_code: Optional source code for infrastructure detection

        Returns:
            List of findings
        """
        findings: List[Finding] = []

        for pattern in patterns:
            pattern_type = pattern.get('type', '')

            # Check original patterns (AGENT-001)
            if pattern_type == 'shell_true' or pattern_type == 'dangerous_function_call':
                # Check if this matches AGENT-001 (Command Injection)
                if self._is_command_injection(pattern):
                    finding = self._create_finding_from_pattern(
                        rule_id="AGENT-001",
                        pattern=pattern,
                        file_path=file_path,
                        source_code=source_code
                    )
                    if finding:
                        findings.append(finding)

            # Check OWASP Agentic patterns
            if pattern_type in self.PATTERN_TYPE_TO_RULE_MAP:
                rule_id = self.PATTERN_TYPE_TO_RULE_MAP[pattern_type]
                finding = self._create_finding_from_pattern(
                    rule_id=rule_id,
                    pattern=pattern,
                    file_path=file_path,
                    source_code=source_code
                )
                if finding:
                    findings.append(finding)

        # v0.6.0: Deduplicate overlapping ASI-01 findings on same line
        # AGENT-010 (general f-string prompt) and AGENT-027 (LangChain message) overlap
        findings = self._deduplicate_findings(findings)

        return findings

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Remove duplicate findings on the same line when rules overlap.

        Prioritization rules:
        - Keep AGENT-010 over AGENT-027 (both detect f-string system prompts)
        - Keep more specific rules over general rules

        Args:
            findings: List of findings to deduplicate

        Returns:
            Deduplicated findings list
        """
        # Track findings by file:line
        findings_by_location: Dict[str, List[Finding]] = {}
        for f in findings:
            loc = f.location
            key = f"{loc.file_path}:{loc.start_line}"
            if key not in findings_by_location:
                findings_by_location[key] = []
            findings_by_location[key].append(f)

        result: List[Finding] = []
        for loc_key, loc_findings in findings_by_location.items():
            if len(loc_findings) == 1:
                result.append(loc_findings[0])
                continue

            # Multiple findings on same line - apply deduplication rules
            rule_ids = {f.rule_id for f in loc_findings}

            # Overlapping rules that should be deduplicated
            # AGENT-010 (general) vs AGENT-027 (LangChain-specific) - keep AGENT-010
            if 'AGENT-010' in rule_ids and 'AGENT-027' in rule_ids:
                # Keep AGENT-010, remove AGENT-027
                loc_findings = [f for f in loc_findings if f.rule_id != 'AGENT-027']

            result.extend(loc_findings)

        return result

    def evaluate_credentials(
        self,
        content: str,
        file_path: str
    ) -> List[Finding]:
        """
        Check content for hardcoded credentials.

        Args:
            content: File content to scan
            file_path: Source file path

        Returns:
            List of credential exposure findings
        """
        findings: List[Finding] = []
        lines = content.splitlines()

        for pattern, description in self.CREDENTIAL_PATTERNS:
            for line_num, line in enumerate(lines, start=1):
                matches = pattern.finditer(line)
                for match in matches:
                    finding = Finding(
                        rule_id="AGENT-004",
                        title="Hardcoded Credentials",
                        description=f"Found {description} in source code",
                        severity=Severity.CRITICAL,
                        category=Category.CREDENTIAL_EXPOSURE,
                        location=Location(
                            file_path=file_path,
                            start_line=line_num,
                            end_line=line_num,
                            start_column=match.start(),
                            end_column=match.end(),
                            snippet=self._mask_credential(line)
                        ),
                        cwe_id="CWE-798",
                        owasp_id="ASI-04",  # Supply Chain Vulnerabilities
                        remediation=Remediation(
                            description="Use environment variables or a secrets manager",
                            code_example="api_key = os.environ.get('API_KEY')"
                        )
                    )
                    findings.append(finding)

        return findings

    def evaluate_mcp_config(
        self,
        servers: List[Dict[str, Any]],
        file_path: str
    ) -> List[Finding]:
        """
        Evaluate MCP server configurations for security issues.

        Args:
            servers: List of MCP server configurations
            file_path: Config file path

        Returns:
            List of findings
        """
        findings: List[Finding] = []

        for server in servers:
            server_name = server.get('name', 'unknown')
            server_url = server.get('url', '')
            env_vars = server.get('env', {})
            is_verified = server.get('verified', False)

            # Check for unverified servers (AGENT-005)
            if not is_verified and server_url:
                if not self._is_trusted_source(server_url):
                    finding = Finding(
                        rule_id="AGENT-005",
                        title="Unverified MCP Server",
                        description=f"MCP server '{server_name}' lacks signature verification",
                        severity=Severity.HIGH,
                        category=Category.SUPPLY_CHAIN,
                        location=Location(
                            file_path=file_path,
                            start_line=server.get('_line', 1),
                            end_line=server.get('_line', 1),
                            snippet=f"server: {server_name}"
                        ),
                        cwe_id="CWE-494",
                        owasp_id="ASI-04",  # Supply Chain Vulnerabilities
                        remediation=Remediation(
                            description="Use verified MCP servers from trusted registries",
                            reference_url="https://modelcontextprotocol.io/docs/security"
                        )
                    )
                    findings.append(finding)

            # Check for credentials in env vars (AGENT-004)
            for key, value in env_vars.items():
                if isinstance(value, str):
                    for pattern, description in self.CREDENTIAL_PATTERNS:
                        if pattern.search(value):
                            finding = Finding(
                                rule_id="AGENT-004",
                                title="Hardcoded Credentials in MCP Config",
                                description=f"Found {description} in environment variable '{key}'",
                                severity=Severity.CRITICAL,
                                category=Category.CREDENTIAL_EXPOSURE,
                                location=Location(
                                    file_path=file_path,
                                    start_line=server.get('_line', 1),
                                    end_line=server.get('_line', 1),
                                    snippet=f"{key}=***REDACTED***"
                                ),
                                cwe_id="CWE-798",
                                owasp_id="ASI-04",  # Supply Chain Vulnerabilities
                                remediation=Remediation(
                                    description="Use environment variables from the host system"
                                )
                            )
                            findings.append(finding)

        return findings

    def evaluate_permission_scope(
        self,
        tools: List[Any],
        file_path: str
    ) -> List[Finding]:
        """
        Check for excessive tool permissions (AGENT-002).

        Args:
            tools: List of tool definitions
            file_path: Source file path

        Returns:
            List of findings
        """
        findings: List[Finding] = []

        if len(tools) > 15:
            finding = Finding(
                rule_id="AGENT-002",
                title="Excessive Agent Permissions",
                description=f"Agent has {len(tools)} tools configured, which may be excessive",
                severity=Severity.MEDIUM,
                category=Category.EXCESSIVE_PERMISSION,
                location=Location(
                    file_path=file_path,
                    start_line=1,
                    end_line=1,
                    snippet=f"Total tools: {len(tools)}"
                ),
                cwe_id="CWE-250",
                confidence=0.7,  # Lower confidence as this is heuristic
                remediation=Remediation(
                    description="Consider splitting into multiple specialized agents"
                )
            )
            findings.append(finding)

        # Check for high-risk permission combinations
        high_risk_count = sum(
            1 for t in tools
            if hasattr(t, 'calculate_risk_score') and t.calculate_risk_score() > 5.0
        )

        if high_risk_count > 5:
            finding = Finding(
                rule_id="AGENT-002",
                title="Multiple High-Risk Tools",
                description=f"Agent has {high_risk_count} high-risk tools",
                severity=Severity.HIGH,
                category=Category.EXCESSIVE_PERMISSION,
                location=Location(
                    file_path=file_path,
                    start_line=1,
                    end_line=1,
                    snippet=f"High-risk tools: {high_risk_count}"
                ),
                cwe_id="CWE-250",
                remediation=Remediation(
                    description="Review and reduce high-risk tool permissions"
                )
            )
            findings.append(finding)

        return findings

    def _evaluate_rule(
        self,
        rule: Dict[str, Any],
        context: MatchContext
    ) -> List[Finding]:
        """Evaluate a single rule against the context."""
        findings: List[Finding] = []

        detection = rule.get('detection', {})
        patterns = detection.get('patterns', [])

        for pattern in patterns:
            pattern_type = pattern.get('type', '')

            if pattern_type == 'python_ast':
                # Match against dangerous patterns from Python scanner
                matches = self._match_python_ast_pattern(
                    pattern,
                    context.dangerous_patterns
                )
                for match in matches:
                    finding = self._create_finding_from_rule(
                        rule, context.file_path, match,
                        source_code=context.source_code
                    )
                    findings.append(finding)

            elif pattern_type == 'function_call':
                # Match against function calls
                matches = self._match_function_calls(
                    pattern,
                    context.function_calls
                )
                for match in matches:
                    finding = self._create_finding_from_rule(
                        rule, context.file_path, match,
                        source_code=context.source_code
                    )
                    findings.append(finding)

            elif pattern_type == 'regex':
                # Match against source code
                if context.source_code:
                    matches = self._match_regex_patterns(
                        pattern.get('patterns', []),
                        context.source_code
                    )
                    for match in matches:
                        finding = self._create_finding_from_rule(
                            rule, context.file_path, match,
                            source_code=context.source_code
                        )
                        findings.append(finding)

        return findings

    def _match_python_ast_pattern(
        self,
        pattern: Dict[str, Any],
        dangerous_patterns: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Match Python AST patterns."""
        matches = []
        match_patterns = pattern.get('match', [])

        for dp in dangerous_patterns:
            func_name = dp.get('function', '')
            for mp in match_patterns:
                # Simple substring matching for now
                if func_name in mp or mp.split('(')[0] in func_name:
                    matches.append(dp)
                    break

        return matches

    def _match_function_calls(
        self,
        pattern: Dict[str, Any],
        function_calls: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Match function call patterns."""
        matches = []
        target_functions = pattern.get('functions', [])
        required_args = pattern.get('arguments', {})

        for call in function_calls:
            call_name = call.get('name', '')
            if call_name in target_functions:
                # Check required arguments if specified
                if required_args:
                    # This would need the actual call arguments
                    # For now, just match on function name
                    pass
                matches.append(call)

        return matches

    def _match_regex_patterns(
        self,
        patterns: List[str],
        content: str
    ) -> List[Dict[str, Any]]:
        """Match regex patterns against content."""
        matches = []
        lines = content.splitlines()

        for pattern_str in patterns:
            try:
                pattern = re.compile(pattern_str)
                for line_num, line in enumerate(lines, start=1):
                    if pattern.search(line):
                        matches.append({
                            'line': line_num,
                            'snippet': line.strip(),
                            'pattern': pattern_str
                        })
            except re.error as e:
                logger.warning(f"Invalid regex pattern: {pattern_str}: {e}")

        return matches

    def _is_command_injection(self, pattern: Dict[str, Any]) -> bool:
        """Check if a pattern represents command injection."""
        func_name = pattern.get('function', '')
        has_tainted = pattern.get('has_tainted_input', False)

        # shell=True is always risky
        if pattern.get('type') == 'shell_true':
            return True

        # Dangerous functions with tainted input
        dangerous_funcs = ['os.system', 'eval', 'exec', 'os.popen']
        if func_name in dangerous_funcs and has_tainted:
            return True

        return False

    def _create_finding_from_pattern(
        self,
        rule_id: str,
        pattern: Dict[str, Any],
        file_path: str,
        source_code: Optional[str] = None
    ) -> Optional[Finding]:
        """Create a finding from a matched pattern.

        v0.8.0: Now passes source_code for infrastructure detection.
        """
        rule = self._rules.get(rule_id)
        if not rule:
            return None

        return self._create_finding_from_rule(rule, file_path, pattern, source_code=source_code)

    # Privilege rules that should NOT be dampened by infrastructure context
    # These rules are critical even in sandbox/infrastructure code
    PRIVILEGE_EXEMPT_RULES = {
        "AGENT-043",  # Daemon privileges
        "AGENT-044",  # Sudoers NOPASSWD
        "AGENT-046",  # System credential store access
    }

    # Rules that benefit from infrastructure context detection
    INFRASTRUCTURE_DAMPENED_RULES = {
        "AGENT-001",  # Command injection
        "AGENT-047",  # Subprocess without sandbox
    }

    def _create_finding_from_rule(
        self,
        rule: Dict[str, Any],
        file_path: str,
        match: Dict[str, Any],
        source_code: Optional[str] = None
    ) -> Finding:
        """
        Create a Finding from a rule and match.

        v0.8.0: Applies per-rule context multipliers for FP reduction.
                Also applies infrastructure detection for AGENT-001/047.
        """
        remediation_data = rule.get('remediation', {})
        remediation = None
        if remediation_data:
            remediation = Remediation(
                description=remediation_data.get('description', ''),
                code_example=remediation_data.get('code_example'),
                reference_url=remediation_data.get('references', [None])[0]
                if remediation_data.get('references') else None
            )

        # Support both owasp_id and owasp_agentic_id
        owasp_id = rule.get('owasp_agentic_id') or rule.get('owasp_id')

        # v0.8.0: Apply per-rule context multipliers
        rule_id = rule['id']
        file_context = classify_file_context(file_path)
        context_multiplier = get_context_multiplier(rule_id, file_context)

        base_confidence = match.get('confidence', 1.0)
        confidence = base_confidence * context_multiplier

        # Log context adjustment if significant
        if context_multiplier < 1.0:
            logger.debug(
                f"Context adjustment: {rule_id} in {file_context.value} "
                f"({base_confidence:.2f} × {context_multiplier:.2f} = {confidence:.2f})"
            )

        # v0.8.0: Infrastructure detection for AGENT-001/047
        # These rules should be dampened in sandbox/container building code
        infrastructure_context = False
        infrastructure_note = None

        if (rule_id in self.INFRASTRUCTURE_DAMPENED_RULES and
                rule_id not in self.PRIVILEGE_EXEMPT_RULES):
            # Content-based detection if source available
            if source_code:
                is_infra, infra_conf, infra_reason = detect_infrastructure_context(
                    file_path, source_code
                )
                if is_infra:
                    # Damping proportional to infrastructure confidence
                    # infra_conf=0.50 → ×0.65, infra_conf=0.90 → ×0.37
                    damping = 1.0 - (infra_conf * 0.70)
                    confidence *= damping
                    infrastructure_context = True
                    infrastructure_note = (
                        f"Infrastructure/sandbox code detected ({infra_reason}). "
                        "The flagged operation may be architecturally intentional."
                    )
                    logger.debug(
                        f"Infrastructure damping: {rule_id} × {damping:.2f} "
                        f"(infra_conf={infra_conf:.2f})"
                    )
            # Path-based detection as fallback
            elif file_context == FileContext.INFRASTRUCTURE:
                # File path already classified as infrastructure - apply damping
                confidence *= 0.50
                infrastructure_context = True
                infrastructure_note = (
                    "File is in infrastructure context. "
                    "The flagged operation may be architecturally intentional."
                )

        tier = confidence_to_tier(confidence)

        finding = Finding(
            rule_id=rule['id'],
            title=rule['title'],
            description=rule.get('description', ''),
            severity=Severity(rule['severity'].lower()),
            category=Category(rule['category'].lower()),
            location=Location(
                file_path=file_path,
                start_line=match.get('line', 1),
                end_line=match.get('line', 1),
                snippet=match.get('snippet', '')
            ),
            cwe_id=rule.get('cwe_id'),
            owasp_id=owasp_id,
            remediation=remediation,
            confidence=confidence,
            tier=tier,
        )

        # Add mitigation metadata if present
        if match.get('mitigation_detected'):
            finding.metadata['mitigation_detected'] = match['mitigation_detected']

        # v0.8.0: Add infrastructure context annotation
        if infrastructure_context:
            finding.metadata['infrastructure_context'] = True
            if infrastructure_note:
                finding.metadata['note'] = infrastructure_note

        return finding

    def _is_trusted_source(self, url: str) -> bool:
        """Check if a URL is from a trusted source."""
        trusted_prefixes = [
            "docker.io/mcp-catalog/",
            "ghcr.io/anthropics/",
            "ghcr.io/modelcontextprotocol/",
        ]
        return any(url.startswith(prefix) for prefix in trusted_prefixes)

    def _mask_credential(self, line: str) -> str:
        """Mask credentials in a line for safe display."""
        # Replace potential credentials with asterisks
        masked = re.sub(
            r'(["\']?)([A-Za-z0-9_-]{20,})(["\']?)',
            r'\1***REDACTED***\3',
            line
        )
        return masked.strip()
