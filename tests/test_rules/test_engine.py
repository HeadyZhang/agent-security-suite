"""Tests for the rule engine."""

import pytest
from pathlib import Path

from agent_core.rules.engine import RuleEngine, MatchContext
from agent_core.models.risk import Severity, Category


class TestRuleEngine:
    """Tests for RuleEngine class."""

    @pytest.fixture
    def engine(self):
        """Create a rule engine instance."""
        return RuleEngine()

    @pytest.fixture
    def engine_with_rules(self, engine):
        """Create an engine with loaded rules."""
        rules_dir = Path(__file__).parent.parent.parent / "rules" / "builtin"
        if rules_dir.exists():
            engine.add_builtin_rules_dir(rules_dir)
            engine.load_rules()
        return engine

    def test_engine_initialization(self, engine):
        """Test engine initializes correctly."""
        assert engine._rules == {}
        assert engine.loader is not None

    def test_load_rules(self, engine_with_rules):
        """Test that rules are loaded."""
        assert len(engine_with_rules._rules) > 0

    def test_evaluate_empty_context(self, engine_with_rules):
        """Test evaluation with empty context."""
        context = MatchContext(file_path="test.py")
        findings = engine_with_rules.evaluate(context)
        assert isinstance(findings, list)


class TestDangerousPatternEvaluation:
    """Tests for dangerous pattern evaluation."""

    @pytest.fixture
    def engine(self):
        engine = RuleEngine()
        rules_dir = Path(__file__).parent.parent.parent / "rules" / "builtin"
        if rules_dir.exists():
            engine.add_builtin_rules_dir(rules_dir)
            engine.load_rules()
        return engine

    def test_detects_shell_true_pattern(self, engine):
        """Test detection of shell=True pattern."""
        patterns = [
            {
                'type': 'shell_true',
                'function': 'subprocess.run',
                'line': 10,
                'snippet': 'subprocess.run(cmd, shell=True)',
                'has_tainted_input': True
            }
        ]

        findings = engine.evaluate_dangerous_patterns(patterns, "agent.py")

        assert len(findings) >= 1
        finding = findings[0]
        assert finding.rule_id == "AGENT-001"
        assert finding.severity == Severity.CRITICAL

    def test_detects_os_system(self, engine):
        """Test detection of os.system with tainted input."""
        patterns = [
            {
                'type': 'dangerous_function_call',
                'function': 'os.system',
                'line': 15,
                'snippet': 'os.system(user_input)',
                'has_tainted_input': True
            }
        ]

        findings = engine.evaluate_dangerous_patterns(patterns, "agent.py")
        assert any(f.rule_id == "AGENT-001" for f in findings)

    def test_detects_eval(self, engine):
        """Test detection of eval with tainted input."""
        patterns = [
            {
                'type': 'dangerous_function_call',
                'function': 'eval',
                'line': 20,
                'snippet': 'eval(user_code)',
                'has_tainted_input': True
            }
        ]

        findings = engine.evaluate_dangerous_patterns(patterns, "agent.py")
        assert any(f.rule_id == "AGENT-001" for f in findings)


class TestCredentialEvaluation:
    """Tests for credential detection."""

    @pytest.fixture
    def engine(self):
        return RuleEngine()

    def test_detects_aws_key(self, engine):
        """Test AWS access key detection."""
        content = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        findings = engine.evaluate_credentials(content, "config.py")

        assert len(findings) == 1
        assert findings[0].rule_id == "AGENT-004"
        assert "AWS" in findings[0].description
        assert findings[0].severity == Severity.CRITICAL

    def test_detects_openai_key(self, engine):
        """Test OpenAI API key detection."""
        actual_key = 'api_key = "sk-' + 'a' * 48 + '"'
        findings = engine.evaluate_credentials(actual_key, "config.py")

        assert len(findings) >= 1
        assert any(f.rule_id == "AGENT-004" for f in findings)

    def test_detects_github_token(self, engine):
        """Test GitHub PAT detection."""
        content = 'token = "ghp_' + 'a' * 36 + '"'
        findings = engine.evaluate_credentials(content, "config.py")

        assert len(findings) >= 1
        assert findings[0].rule_id == "AGENT-004"

    def test_detects_generic_api_key(self, engine):
        """Test generic API key detection."""
        content = 'api_key = "abcdefghij1234567890abcd"'
        findings = engine.evaluate_credentials(content, "config.py")

        assert len(findings) >= 1

    def test_masks_credentials(self, engine):
        """Test that credentials are masked in snippets."""
        content = 'API_KEY = "AKIAIOSFODNN7EXAMPLE"'
        findings = engine.evaluate_credentials(content, "config.py")

        # May find multiple patterns (AWS key + generic API key pattern)
        assert len(findings) >= 1
        # The masking replaces long strings with ***REDACTED***
        snippet = findings[0].location.snippet
        assert "REDACTED" in snippet or "***" in snippet

    def test_no_false_positives_on_short_strings(self, engine):
        """Test no false positives on short strings."""
        content = 'name = "hello"'
        findings = engine.evaluate_credentials(content, "config.py")

        # Short strings shouldn't trigger credential detection
        # unless they match specific patterns
        credential_findings = [f for f in findings if "Credentials" in f.title]
        assert len(credential_findings) == 0


class TestMCPConfigEvaluation:
    """Tests for MCP config evaluation."""

    @pytest.fixture
    def engine(self):
        return RuleEngine()

    def test_detects_unverified_server(self, engine):
        """Test detection of unverified MCP server."""
        servers = [
            {
                'name': 'custom-server',
                'url': 'http://untrusted.example.com/mcp',
                'verified': False,
                '_line': 5
            }
        ]

        findings = engine.evaluate_mcp_config(servers, "mcp.json")

        assert len(findings) >= 1
        assert any(f.rule_id == "AGENT-005" for f in findings)

    def test_trusted_source_no_finding(self, engine):
        """Test that trusted sources don't trigger findings."""
        servers = [
            {
                'name': 'official-server',
                'url': 'ghcr.io/anthropics/mcp-server',
                'verified': False,
                '_line': 5
            }
        ]

        findings = engine.evaluate_mcp_config(servers, "mcp.json")

        # Should not flag as unverified since it's from trusted source
        unverified_findings = [f for f in findings if f.rule_id == "AGENT-005"]
        assert len(unverified_findings) == 0

    def test_detects_credentials_in_env(self, engine):
        """Test detection of hardcoded credentials in env vars."""
        servers = [
            {
                'name': 'server',
                'url': 'http://example.com',
                'env': {
                    'API_KEY': 'AKIAIOSFODNN7EXAMPLE'
                },
                '_line': 5
            }
        ]

        findings = engine.evaluate_mcp_config(servers, "mcp.json")

        assert any(f.rule_id == "AGENT-004" for f in findings)


class TestPermissionScopeEvaluation:
    """Tests for permission scope evaluation."""

    @pytest.fixture
    def engine(self):
        return RuleEngine()

    def test_detects_excessive_tools(self, engine):
        """Test detection of too many tools."""
        from agent_core.models.tool import ToolDefinition

        tools = [
            ToolDefinition(
                name=f"tool_{i}",
                description=f"Tool {i}",
                source_file="agent.py",
                source_line=i+1
            )
            for i in range(20)
        ]

        findings = engine.evaluate_permission_scope(tools, "agent.py")

        assert len(findings) >= 1
        assert any(f.rule_id == "AGENT-002" for f in findings)
        # Check that the message mentions the tool count
        assert any("20" in f.description for f in findings)

    def test_acceptable_tool_count(self, engine):
        """Test that acceptable tool count doesn't trigger finding."""
        from agent_core.models.tool import ToolDefinition

        tools = [
            ToolDefinition(
                name=f"tool_{i}",
                description=f"Tool {i}",
                source_file="agent.py",
                source_line=i+1
            )
            for i in range(5)
        ]

        findings = engine.evaluate_permission_scope(tools, "agent.py")

        # Should not flag for excessive tools (threshold is 15)
        excessive_findings = [
            f for f in findings
            if f.rule_id == "AGENT-002" and "tools configured" in f.description
        ]
        assert len(excessive_findings) == 0
