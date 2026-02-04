"""Tests for OWASP Agentic Top 10 rule coverage."""

import pytest
from pathlib import Path
from typing import List

from agent_audit.scanners.python_scanner import PythonScanner
from agent_audit.rules.engine import RuleEngine
from agent_audit.models.finding import Finding


class TestOWASPAgenticCoverage:
    """Test suite for OWASP Agentic Top 10 detection coverage."""

    @pytest.fixture
    def scanner(self):
        """Create a Python scanner instance."""
        return PythonScanner()

    @pytest.fixture
    def rule_engine(self):
        """Create a rule engine with builtin rules loaded."""
        engine = RuleEngine()
        # Find rules directory
        possible_dirs = [
            Path(__file__).parent.parent / "rules" / "builtin",
            Path(__file__).parent.parent.parent / "rules" / "builtin",
        ]
        for rules_dir in possible_dirs:
            if rules_dir.exists():
                engine.add_builtin_rules_dir(rules_dir)
                break
        engine.load_rules()
        return engine

    @pytest.fixture
    def fixture_path(self):
        """Path to the OWASP full fixture file."""
        return Path(__file__).parent / "fixtures" / "vulnerable_agents" / "owasp_agentic_full.py"

    def _scan_and_evaluate(self, fixture_name: str) -> List[Finding]:
        """Scan a fixture file and evaluate patterns through rule engine."""
        scanner = PythonScanner()
        engine = RuleEngine()

        # Find rules directory
        possible_dirs = [
            Path(__file__).parent.parent / "rules" / "builtin",
            Path(__file__).parent.parent.parent / "rules" / "builtin",
        ]
        for rules_dir in possible_dirs:
            if rules_dir.exists():
                engine.add_builtin_rules_dir(rules_dir)
                break
        engine.load_rules()

        fixture_path = Path(__file__).parent / "fixtures" / "vulnerable_agents" / fixture_name

        results = scanner.scan(fixture_path)
        findings: List[Finding] = []

        for result in results:
            result_findings = engine.evaluate_dangerous_patterns(
                result.dangerous_patterns, result.source_file
            )
            findings.extend(result_findings)

        return findings

    # --- ASI-01: Agent Goal Hijack ---

    def test_asi01_prompt_injection_fstring(self):
        """Test detection of f-string in system prompt (AGENT-010)."""
        findings = self._scan_and_evaluate("owasp_agentic_full.py")
        asi01_findings = [f for f in findings if f.owasp_id == "ASI-01"]
        assert len(asi01_findings) >= 1, \
            f"Expected >= 1 ASI-01 findings, got {len(asi01_findings)}"

    def test_asi01_has_agent010(self):
        """Test that AGENT-010 is detected for prompt injection."""
        findings = self._scan_and_evaluate("owasp_agentic_full.py")
        rule_ids = {f.rule_id for f in findings if f.owasp_id == "ASI-01"}
        assert "AGENT-010" in rule_ids, \
            f"Expected AGENT-010 in ASI-01 findings, got {rule_ids}"

    # --- ASI-03: Identity & Privilege Abuse ---

    def test_asi03_excessive_tools(self):
        """Test detection of excessive tools (AGENT-014)."""
        findings = self._scan_and_evaluate("owasp_agentic_full.py")
        asi03_findings = [f for f in findings if f.owasp_id == "ASI-03"]
        assert len(asi03_findings) >= 1, \
            f"Expected >= 1 ASI-03 findings, got {len(asi03_findings)}"

    # --- ASI-05: Unexpected Code Execution ---

    def test_asi05_eval_in_tool(self):
        """Test detection of eval/exec in @tool (AGENT-017)."""
        findings = self._scan_and_evaluate("owasp_agentic_full.py")
        asi05_findings = [f for f in findings if f.owasp_id == "ASI-05"]
        assert len(asi05_findings) >= 1, \
            f"Expected >= 1 ASI-05 findings, got {len(asi05_findings)}"

    # --- ASI-06: Memory Poisoning ---

    def test_asi06_unsanitized_memory(self):
        """Test detection of unsanitized memory writes (AGENT-018/019)."""
        findings = self._scan_and_evaluate("owasp_agentic_full.py")
        asi06_findings = [f for f in findings if f.owasp_id == "ASI-06"]
        assert len(asi06_findings) >= 1, \
            f"Expected >= 1 ASI-06 findings, got {len(asi06_findings)}"

    # --- ASI-07: Insecure Inter-Agent Communication ---

    def test_asi07_multi_agent_no_auth(self):
        """Test detection of multi-agent without auth (AGENT-020)."""
        findings = self._scan_and_evaluate("owasp_agentic_full.py")
        asi07_findings = [f for f in findings if f.owasp_id == "ASI-07"]
        assert len(asi07_findings) >= 1, \
            f"Expected >= 1 ASI-07 findings, got {len(asi07_findings)}"

    # --- ASI-08: Cascading Failures ---

    def test_asi08_no_circuit_breaker(self):
        """Test detection of missing circuit breaker (AGENT-021)."""
        findings = self._scan_and_evaluate("owasp_agentic_full.py")
        asi08_findings = [f for f in findings if f.owasp_id == "ASI-08"]
        assert len(asi08_findings) >= 1, \
            f"Expected >= 1 ASI-08 findings, got {len(asi08_findings)}"

    def test_asi08_tool_without_error_handling(self):
        """Test detection of tool without error handling (AGENT-022)."""
        findings = self._scan_and_evaluate("owasp_agentic_full.py")
        asi08_findings = [f for f in findings if f.owasp_id == "ASI-08"]
        rule_ids = {f.rule_id for f in asi08_findings}
        assert "AGENT-022" in rule_ids, \
            f"Expected AGENT-022 in ASI-08 findings, got rule_ids={rule_ids}"

    # --- ASI-09: Trust Exploitation ---

    def test_asi09_opaque_output(self):
        """Test detection of opaque agent output (AGENT-023)."""
        findings = self._scan_and_evaluate("owasp_agentic_full.py")
        asi09_findings = [f for f in findings if f.owasp_id == "ASI-09"]
        assert len(asi09_findings) >= 1, \
            f"Expected >= 1 ASI-09 findings, got {len(asi09_findings)}"

    # --- ASI-10: Rogue Agents ---

    def test_asi10_no_kill_switch(self):
        """Test detection of agent without kill switch (AGENT-024)."""
        findings = self._scan_and_evaluate("owasp_agentic_full.py")
        asi10_findings = [f for f in findings if f.owasp_id == "ASI-10"]
        assert len(asi10_findings) >= 1, \
            f"Expected >= 1 ASI-10 findings, got {len(asi10_findings)}"

    def test_asi10_no_observability(self):
        """Test detection of agent without observability (AGENT-025)."""
        findings = self._scan_and_evaluate("owasp_agentic_full.py")
        asi10_findings = [f for f in findings if f.owasp_id == "ASI-10"]
        rule_ids = {f.rule_id for f in asi10_findings}
        # Should have either AGENT-024 or AGENT-025
        assert "AGENT-024" in rule_ids or "AGENT-025" in rule_ids, \
            f"Expected AGENT-024 or AGENT-025 in ASI-10 findings, got {rule_ids}"

    # --- Safe examples should not trigger ---

    def test_safe_bounded_agent_no_asi08(self):
        """Safe bounded agent should not trigger ASI-08 circuit breaker."""
        scanner = PythonScanner()
        fixture_path = Path(__file__).parent / "fixtures" / "vulnerable_agents" / "owasp_agentic_full.py"
        results = scanner.scan(fixture_path)

        for result in results:
            for pattern in result.dangerous_patterns:
                if pattern.get('owasp_id') == 'ASI-08':
                    if 'safe_bounded_agent' in pattern.get('snippet', ''):
                        pytest.fail("safe_bounded_agent should not trigger ASI-08")
