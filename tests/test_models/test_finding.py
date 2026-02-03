"""Tests for the Finding model."""

import pytest
from datetime import datetime

from agent_core.models.finding import Finding, Remediation
from agent_core.models.risk import Severity, Category, Location


class TestFinding:
    """Tests for Finding dataclass."""

    @pytest.fixture
    def sample_finding(self) -> Finding:
        """Create a sample finding for tests."""
        return Finding(
            rule_id="AGENT-001",
            title="Command Injection via Unsanitized Input",
            description="Tool accepts user input passed directly to shell execution",
            severity=Severity.CRITICAL,
            category=Category.COMMAND_INJECTION,
            location=Location(
                file_path="tools/shell.py",
                start_line=23,
                end_line=23,
                start_column=4,
                end_column=50,
                snippet="subprocess.run(user_input, shell=True)"
            ),
            confidence=0.9,
            cwe_id="CWE-78",
            owasp_id="OWASP-AGENT-02",
            remediation=Remediation(
                description="Use shlex.quote() and avoid shell=True",
                code_example='subprocess.run(["ls", shlex.quote(user_input)])',
                reference_url="https://owasp.org/www-community/attacks/Command_Injection"
            )
        )

    def test_finding_creation(self, sample_finding: Finding):
        """Test that a Finding can be created with all fields."""
        assert sample_finding.rule_id == "AGENT-001"
        assert sample_finding.title == "Command Injection via Unsanitized Input"
        assert sample_finding.severity == Severity.CRITICAL
        assert sample_finding.category == Category.COMMAND_INJECTION
        assert sample_finding.location.file_path == "tools/shell.py"
        assert sample_finding.location.start_line == 23
        assert sample_finding.confidence == 0.9
        assert sample_finding.cwe_id == "CWE-78"
        assert sample_finding.owasp_id == "OWASP-AGENT-02"

    def test_finding_default_values(self):
        """Test default values for optional fields."""
        finding = Finding(
            rule_id="TEST-001",
            title="Test Finding",
            description="Test description",
            severity=Severity.LOW,
            category=Category.COMMAND_INJECTION,
            location=Location(
                file_path="test.py",
                start_line=1,
                end_line=1
            )
        )

        assert finding.confidence == 1.0
        assert finding.suppressed is False
        assert finding.suppressed_reason is None
        assert finding.suppressed_by is None
        assert finding.cwe_id is None
        assert finding.remediation is None
        assert isinstance(finding.metadata, dict)
        assert isinstance(finding.detected_at, datetime)

    def test_is_actionable_default(self, sample_finding: Finding):
        """Test is_actionable with default threshold."""
        # Default confidence is 0.9, default threshold is 0.5
        assert sample_finding.is_actionable() is True

    def test_is_actionable_high_threshold(self, sample_finding: Finding):
        """Test is_actionable with high confidence threshold."""
        # Confidence is 0.9, threshold is 0.95
        assert sample_finding.is_actionable(min_confidence=0.95) is False

    def test_is_actionable_low_confidence(self):
        """Test is_actionable with low confidence finding."""
        finding = Finding(
            rule_id="TEST-001",
            title="Low Confidence Finding",
            description="Might be a false positive",
            severity=Severity.MEDIUM,
            category=Category.COMMAND_INJECTION,
            location=Location(file_path="test.py", start_line=1, end_line=1),
            confidence=0.3
        )

        assert finding.is_actionable(min_confidence=0.5) is False
        assert finding.is_actionable(min_confidence=0.2) is True

    def test_is_actionable_suppressed(self, sample_finding: Finding):
        """Test that suppressed findings are not actionable."""
        sample_finding.suppressed = True
        sample_finding.suppressed_reason = "False positive in test code"
        sample_finding.suppressed_by = ".agent-audit.yaml"

        assert sample_finding.is_actionable() is False

    def test_to_sarif(self, sample_finding: Finding):
        """Test SARIF conversion."""
        sarif = sample_finding.to_sarif()

        assert sarif["ruleId"] == "AGENT-001"
        assert sarif["level"] == "error"  # CRITICAL maps to error
        assert sarif["message"]["text"] == sample_finding.description
        assert sarif["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "tools/shell.py"
        assert sarif["locations"][0]["physicalLocation"]["region"]["startLine"] == 23
        assert sarif["locations"][0]["physicalLocation"]["region"]["startColumn"] == 4
        assert "fingerprints" in sarif
        assert "primary" in sarif["fingerprints"]

    def test_to_sarif_severity_mapping(self):
        """Test SARIF level mapping for different severities."""
        severities_to_levels = [
            (Severity.CRITICAL, "error"),
            (Severity.HIGH, "error"),
            (Severity.MEDIUM, "warning"),
            (Severity.LOW, "note"),
            (Severity.INFO, "note"),
        ]

        for severity, expected_level in severities_to_levels:
            finding = Finding(
                rule_id="TEST",
                title="Test",
                description="Test",
                severity=severity,
                category=Category.COMMAND_INJECTION,
                location=Location(file_path="test.py", start_line=1, end_line=1)
            )
            assert finding.to_sarif()["level"] == expected_level

    def test_fingerprint_stability(self, sample_finding: Finding):
        """Test that fingerprint is stable for same finding."""
        fingerprint1 = sample_finding._compute_fingerprint()
        fingerprint2 = sample_finding._compute_fingerprint()

        assert fingerprint1 == fingerprint2
        assert len(fingerprint1) == 16  # SHA256 truncated to 16 chars

    def test_to_dict(self, sample_finding: Finding):
        """Test dictionary conversion for JSON serialization."""
        d = sample_finding.to_dict()

        assert d["rule_id"] == "AGENT-001"
        assert d["severity"] == "critical"
        assert d["category"] == "command_injection"
        assert d["location"]["file_path"] == "tools/shell.py"
        assert d["confidence"] == 0.9
        assert d["remediation"]["description"] == "Use shlex.quote() and avoid shell=True"
        assert "detected_at" in d


class TestLocation:
    """Tests for Location dataclass."""

    def test_location_minimal(self):
        """Test Location with minimal required fields."""
        loc = Location(
            file_path="test.py",
            start_line=10,
            end_line=15
        )

        assert loc.file_path == "test.py"
        assert loc.start_line == 10
        assert loc.end_line == 15
        assert loc.start_column is None
        assert loc.end_column is None
        assert loc.snippet is None

    def test_location_full(self):
        """Test Location with all fields."""
        loc = Location(
            file_path="src/tools/dangerous.py",
            start_line=42,
            end_line=45,
            start_column=8,
            end_column=55,
            snippet="os.system(user_input)"
        )

        assert loc.file_path == "src/tools/dangerous.py"
        assert loc.start_line == 42
        assert loc.end_line == 45
        assert loc.start_column == 8
        assert loc.end_column == 55
        assert loc.snippet == "os.system(user_input)"


class TestRemediation:
    """Tests for Remediation dataclass."""

    def test_remediation_minimal(self):
        """Test Remediation with minimal fields."""
        rem = Remediation(description="Fix the bug")

        assert rem.description == "Fix the bug"
        assert rem.code_example is None
        assert rem.reference_url is None

    def test_remediation_full(self):
        """Test Remediation with all fields."""
        rem = Remediation(
            description="Use parameterized queries",
            code_example="cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            reference_url="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        )

        assert rem.description == "Use parameterized queries"
        assert "cursor.execute" in rem.code_example
        assert "owasp.org" in rem.reference_url


class TestSeverity:
    """Tests for Severity enum comparison."""

    def test_severity_ordering(self):
        """Test that severities can be compared."""
        assert Severity.INFO < Severity.LOW
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL

    def test_severity_equality(self):
        """Test severity equality."""
        assert Severity.HIGH == Severity.HIGH
        assert not (Severity.HIGH == Severity.CRITICAL)

    def test_severity_greater_than(self):
        """Test severity greater than comparison."""
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM >= Severity.MEDIUM
