"""Rule engine for pattern matching and finding generation."""

import re
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from agent_audit.models.finding import Finding, Remediation
from agent_audit.models.risk import Severity, Category, Location
from agent_audit.rules.loader import RuleLoader

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

        # ASI-03: Identity & Privilege Abuse
        'hardcoded_credential_in_agent': 'AGENT-013',
        'excessive_tools': 'AGENT-014',
        'auto_approval': 'AGENT-014',

        # ASI-04: Supply Chain
        'npx_unfixed_version': 'AGENT-015',
        'unofficial_mcp_source': 'AGENT-015',
        'unvalidated_rag_ingestion': 'AGENT-016',

        # ASI-05: RCE
        'unsandboxed_code_exec_in_tool': 'AGENT-017',

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

        # ASI-10: Rogue Agents
        'no_kill_switch': 'AGENT-024',
        'no_observability': 'AGENT-025',
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
        file_path: str
    ) -> List[Finding]:
        """
        Evaluate dangerous patterns detected by scanners.

        Args:
            patterns: List of dangerous patterns from scanner
            file_path: Source file path

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
                        file_path=file_path
                    )
                    if finding:
                        findings.append(finding)

            # Check OWASP Agentic patterns
            if pattern_type in self.PATTERN_TYPE_TO_RULE_MAP:
                rule_id = self.PATTERN_TYPE_TO_RULE_MAP[pattern_type]
                finding = self._create_finding_from_pattern(
                    rule_id=rule_id,
                    pattern=pattern,
                    file_path=file_path
                )
                if finding:
                    findings.append(finding)

        return findings

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
                        rule, context.file_path, match
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
                        rule, context.file_path, match
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
                            rule, context.file_path, match
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
        file_path: str
    ) -> Optional[Finding]:
        """Create a finding from a matched pattern."""
        rule = self._rules.get(rule_id)
        if not rule:
            return None

        return self._create_finding_from_rule(rule, file_path, pattern)

    def _create_finding_from_rule(
        self,
        rule: Dict[str, Any],
        file_path: str,
        match: Dict[str, Any]
    ) -> Finding:
        """Create a Finding from a rule and match."""
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

        return Finding(
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
            confidence=match.get('confidence', 1.0)
        )

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
